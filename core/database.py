import json
import sqlite3
import time
from datetime import datetime
from queue import Queue
from threading import Lock, Thread


class DatabaseManager:
    def __init__(self, db_name='packet.db'):
        self.db_name = db_name
        self.lock = Lock()
        self.batch_queue = Queue()
        self.batch_size = 50  # 批量插入阈值
        self.last_cleanup = time.time()
        self.conn_pool = None  # 新增连接池（简单实现）
        self._init_connection()

        # 初始化数据库
        self._init_db()

        # 启动批量插入线程
        self._start_batch_worker()

    def _init_db(self):
        """初始化数据库表结构（修复初始化顺序问题）"""
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                # 1. 先创建主表（确保表存在）
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        src_mac TEXT,
                        dst_mac TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        src_port TEXT,
                        dst_port TEXT,
                        protocol TEXT,
                        details TEXT,
                        raw_packet BLOB,
                        tls_version TEXT,
                        server_name TEXT,
                        certificate_issuer TEXT,
                        packet_size INTEGER,
                        eth_header_size INTEGER,
                        ip_header_size INTEGER,
                        transport_header_size INTEGER,
                        app_payload_size INTEGER,
                        network_layer TEXT DEFAULT 'Unknown',
                        transport_layer TEXT DEFAULT 'Unknown',
                        application_layer TEXT DEFAULT 'Unknown'
                    )
                """)

                # 2. 添加可能缺失的列（使用参数化方式）
                columns_to_add = [
                    ('network_layer', 'TEXT DEFAULT "Unknown"'),
                    ('transport_layer', 'TEXT DEFAULT "Unknown"'),
                    ('application_layer', 'TEXT DEFAULT "Unknown"')
                ]

                # 获取现有列信息
                cursor = conn.execute("PRAGMA table_info(packets)")
                existing_columns = [row[1] for row in cursor.fetchall()]

                # 遍历需要添加的列
                for column, col_type in columns_to_add:
                    if column not in existing_columns:
                        try:
                            conn.execute(f"""
                                ALTER TABLE packets 
                                ADD COLUMN {column} {col_type}
                            """)
                            print(f"成功添加列 {column}")
                        except sqlite3.OperationalError as e:
                            print(f"添加列 {column} 失败: {str(e)}")

                # 3. 创建索引
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_network 
                    ON packets(network_layer)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_transport 
                    ON packets(transport_layer)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_application 
                    ON packets(application_layer)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_timestamp 
                    ON packets(timestamp)
                """)

                # 4. 优化设置
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous = NORMAL")
                conn.commit()

    def _batch_insert(self, packets):
        """批量插入数据（新增三个协议层字段）"""
        query = """
            INSERT INTO packets (
                timestamp, src_mac, dst_mac,
                src_ip, dst_ip, src_port, dst_port,
                protocol, details, raw_packet,
                tls_version, server_name, certificate_issuer,
                packet_size, eth_header_size,
                ip_header_size, transport_header_size,
                app_payload_size,
                network_layer, transport_layer, application_layer
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        params = []
        for pkt in packets:
            tls_info = pkt.get('details', {}).get('tls', {})
            params.append((
                datetime.now().isoformat(),
                pkt.get('src_mac'),
                pkt.get('dst_mac'),
                pkt.get('src_ip'),
                pkt.get('dst_ip'),
                str(pkt.get('src_port')) if pkt.get('src_port') else None,
                str(pkt.get('dst_port')) if pkt.get('dst_port') else None,
                pkt.get('protocol'),
                json.dumps(pkt.get('details', {})),
                pkt.get('raw_packet'),
                tls_info.get('version'),
                tls_info.get('sni'),
                tls_info.get('certificate', {}).get('issuer'),
                pkt.get('packet_size', 0),
                pkt.get('eth_header_size', 0),
                pkt.get('ip_header_size', 0),
                pkt.get('transport_header_size', 0),
                pkt.get('app_payload_size', 0),
                pkt.get('network_layer'),
                pkt.get('transport_layer'),
                pkt.get('application_layer')

            ))

        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                try:
                    conn.executemany(query, params)
                    conn.commit()
                except sqlite3.Error as e:
                    print(f"Database insert error: {e}")
                except:
                    print("数据库错误")

    def save_packet(self, analysis):
        """添加数据包到处理队列（新增流量计算）"""
        raw_packet = analysis.get('raw_packet', b'')

        # 协议分类判断逻辑
        layer_hierarchy = analysis.get('layer_hierarchy', '')
        layers = layer_hierarchy.split('/') if layer_hierarchy else []

        # 协议类型分类
        PROTO_HIERARCHY = {
            'network': ['IPv4', 'IPv6', 'ARP', 'ICMP'],
            'transport': ['TCP', 'UDP', 'ICMP'],
            'application': ['HTTP', 'DNS', 'HTTPS','SIP',  'FTP', 'SMTP','POP3', 'IMAP']
        }

        # 使用更精确的分类算法
        network_proto = next(
            (p for p in layers if p in PROTO_HIERARCHY['network']),
            None
        )

        transport_proto = next(
            (p for p in layers if p in PROTO_HIERARCHY['transport']),
            None
        )

        application_proto = next(
            (p for p in reversed(layers) if p in PROTO_HIERARCHY['application']),
            None
        )
        # 安全获取嵌套字段
        layer_sizes = analysis.get('layer_sizes', {})
        metadata = analysis.get('metadata', {})
        transport_protocol = metadata.get('transport_protocol')
        transport_header_size = layer_sizes.get(
            transport_protocol,  # 使用协议类型作为键
            {}).get('header_size', 0)
        hierarchy_last = layers[-1] if layers else ''

        db_record = {
            'src_mac': metadata.get('src_mac'),
            'dst_mac': metadata.get('dst_mac'),
            'src_ip': metadata.get('src_ip'),
            'dst_ip': metadata.get('dst_ip'),
            'src_port': metadata.get('src_port'),
            'dst_port': metadata.get('dst_port'),
            'protocol': hierarchy_last,
            'details': analysis.get('details', {}),  # 直接使用原始details
            'raw_packet':raw_packet ,
            'packet_size': metadata.get('packet_size', 0),
            'eth_header_size': layer_sizes.get('Ethernet', {}).get('header_size', 0),
            'ip_header_size': layer_sizes.get('IP', {}).get('header_size', 0),
            'transport_header_size': layer_sizes.get(transport_protocol, {}).get('header_size', 0),
            'app_payload_size': layer_sizes.get(hierarchy_last, {}).get('payload_size', 0),
            'network_layer': network_proto or 'Unknown',
            'transport_layer': transport_proto or 'Unknown',
            'application_layer': application_proto or 'Unknown'
        }
        self.batch_queue.put(db_record)

    def _extract_details(self, analysis):
        """直接使用解析层原始数据"""
        return analysis.get('details', {})

    def _start_batch_worker(self):
        """启动批量插入后台线程（修正方法名）"""

        def worker():
            while True:
                items = []
                # 等待批量数据或超时
                while len(items) < self.batch_size and not self.batch_queue.empty():
                    items.append(self.batch_queue.get())

                if items:
                    self._batch_insert(items)

                # 每小时执行一次清理
                if time.time() - self.last_cleanup > 3600:
                    self.cleanup_old_records(days=7)
                    self.last_cleanup = time.time()

                time.sleep(1)

        Thread(target=worker, daemon=True).start()
    def cleanup_old_records(self, days=30):
        """清理过期记录"""
        cutoff = datetime.now().timestamp() - days * 86400
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                try:
                    conn.execute("""
                        DELETE FROM packets 
                        WHERE timestamp < ?
                    """, (datetime.fromtimestamp(cutoff).isoformat(),))
                    conn.commit()
                except sqlite3.Error as e:
                    print(f"Database cleanup error: {e}")
                except:
                    print("数据库错误")

    def get_protocol_stats(self):
        """获取分层协议统计（增强版）"""
        stats = {'network': {}, 'transport': {}, 'application': {}}
        with self.lock:
            try:
                cursor = self.conn_pool.cursor()
                # 网络层统计（包含ICMP）
                cursor.execute("""
                    SELECT 
                        SUM(CASE WHEN network_layer = 'IPv4' THEN 1 ELSE 0 END) as IPv4,
                        SUM(CASE WHEN network_layer = 'IPv6' THEN 1 ELSE 0 END) as IPv6,
                        SUM(CASE WHEN network_layer = 'ARP' THEN 1 ELSE 0 END) as ARP,
                        SUM(CASE WHEN network_layer = 'ICMP' THEN 1 ELSE 0 END) as ICMP
                    FROM packets
                """)
                stats['network'] = dict(zip(['IPv4', 'IPv6', 'ARP', 'ICMP'], cursor.fetchone()))
                # 传输层统计（直接使用transport_layer字段）
                cursor.execute("""
                    SELECT 
                        SUM(CASE WHEN transport_layer = 'TCP' THEN 1 ELSE 0 END) as TCP,
                        SUM(CASE WHEN transport_layer = 'UDP' THEN 1 ELSE 0 END) as UDP
                    FROM packets
                """)
                stats['transport'] = dict(zip(['TCP', 'UDP'], cursor.fetchone()))
                # 应用层统计
                cursor.execute("""
                    SELECT
                        SUM(CASE WHEN application_layer = 'HTTP' THEN 1 ELSE 0 END) as HTTP,
                        SUM(CASE WHEN application_layer = 'HTTPS' THEN 1 ELSE 0 END) as HTTPS,
                        SUM(CASE WHEN application_layer = 'DNS' THEN 1 ELSE 0 END) as DNS,
                        SUM(CASE WHEN application_layer = 'FTP' THEN 1 ELSE 0 END) as FTP,
                        SUM(CASE WHEN application_layer = 'SMTP' THEN 1 ELSE 0 END) as SMTP
                    FROM packets
                """)
                stats['application'] = dict(zip(['HTTP', 'HTTPS', 'DNS', 'FTP', 'SMTP'], cursor.fetchone()))
            except Exception as e:
                print(f"协议统计查询失败: {str(e)}")
        return stats

    def get_top_ips(self, limit=10):
        """获取通信量最大的IP地址（修正游标使用）"""
        with self.lock:
            try:
                cursor = self.conn_pool.cursor()
                cursor.execute("""
                    SELECT 
                        COALESCE(src_ip, '未知') as ip, 
                        COUNT(*) as count 
                    FROM packets 
                    GROUP BY ip 
                    ORDER BY count DESC 
                    LIMIT ?
                """, (limit,))
                result = cursor.fetchall()
                cursor.close()
                return result
            except Exception as e:
                print(f"TOP IP查询失败: {str(e)}")
                return []

    def get_time_range(self):
        """获取捕获时间范围（修正游标使用）"""
        with self.lock:
            try:
                cursor = self.conn_pool.cursor()
                cursor.execute("""
                    SELECT 
                        MIN(timestamp) as first, 
                        MAX(timestamp) as last 
                    FROM packets
                    WHERE timestamp IS NOT NULL
                """)
                result = cursor.fetchone()
                cursor.close()

                if result and result['first']:
                    return {
                        'first': datetime.fromisoformat(result['first']).strftime('%Y-%m-%d %H:%M:%S'),
                        'last': datetime.fromisoformat(result['last']).strftime('%Y-%m-%d %H:%M:%S')
                    }
                return {'first': '无数据', 'last': '无数据'}
            except Exception as e:
                print(f"时间范围查询失败: {str(e)}")
                return {'first': '错误', 'last': '错误'}

    def get_total_traffic(self):
        """获取精确的总流量（字节）"""
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT SUM(packet_size) FROM packets")
                return cursor.fetchone()[0] or 0

    def get_traffic_breakdown(self):
        """获取流量细分统计"""
        return {
            'total': self.get_total_traffic(),
            'headers': {
                'ethernet': self._sum_column('eth_header_size'),
                'ip': self._sum_column('ip_header_size'),
                'transport': self._sum_column('transport_header_size')
            },
            'payload': self._sum_column('app_payload_size')
        }

    def _sum_column(self, column):
        """通用列求和"""
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT SUM({column}) FROM packets")
                return cursor.fetchone()[0] or 0

    def _init_connection(self):
        """初始化数据库连接（线程安全方式）"""
        with self.lock:
            self.conn_pool = sqlite3.connect(
                self.db_name,
                check_same_thread=False,  # 允许多线程访问
                timeout=30  # 增加超时时间
            )
            self.conn_pool.row_factory = sqlite3.Row  # 启用行对象

    def get_traffic_rates(self, start_time: datetime, end_time: datetime, resolution: str = 'minute'):
        """获取指定时间范围内的流量速率"""
        # 定义时间格式映射
        time_format_map = {
            'second': '%Y-%m-%d %H:%M:%S',
            'minute': '%Y-%m-%d %H:%M',
            'hour': '%Y-%m-%d %H',
            'day': '%Y-%m-%d'
        }

        time_format = time_format_map.get(resolution, '%Y-%m-%d %H:%M')

        query = f"""
            SELECT 
                strftime('{time_format}', timestamp) as time_window,
                SUM(packet_size) as total_bytes 
            FROM packets 
            WHERE timestamp BETWEEN ? AND ?
            GROUP BY time_window
            ORDER BY timestamp
        """
        params = (
            start_time.isoformat(),
            end_time.isoformat()
        )

        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                return [
                    (row['time_window'], row['total_bytes'])
                    for row in cursor.fetchall()
                ]

