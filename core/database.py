import sqlite3
import json
from datetime import datetime
from threading import Lock, Thread
from queue import Queue
import time


class DatabaseManager:
    def __init__(self, db_name='packet.db'):
        self.db_name = db_name
        self.lock = Lock()
        self.batch_queue = Queue()
        self.batch_size = 50  # 批量插入阈值
        self.last_cleanup = time.time()

        # 初始化数据库
        self._init_db()

        # 启动批量插入线程
        self._start_batch_worker()

    def _init_db(self):
        """初始化数据库表结构"""
        with self.lock, sqlite3.connect(self.db_name) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_mac TEXT,
                    dst_mac TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT,
                    details TEXT,
                    raw_hex TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_protocol 
                ON packets(protocol)
            """)
            conn.execute("PRAGMA journal_mode=WAL")  # 启用WAL模式

    def _start_batch_worker(self):
        """启动批量插入后台线程"""

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

    def _batch_insert(self, packets):
        """批量插入数据"""
        query = """
            INSERT INTO packets (
                timestamp, src_mac, dst_mac,
                src_ip, dst_ip, src_port, dst_port,
                protocol, details, raw_hex
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = []

        for pkt in packets:
            params.append((
                datetime.now().isoformat(),
                pkt.get('src_mac'),
                pkt.get('dst_mac'),
                pkt.get('src_ip'),
                pkt.get('dst_ip'),
                pkt.get('src_port'),
                pkt.get('dst_port'),
                pkt.get('protocol'),
                json.dumps(pkt.get('details', {})),
                pkt.get('raw_hex')
            ))

        with self.lock, sqlite3.connect(self.db_name) as conn:
            conn.executemany(query, params)
            conn.commit()

    def save_packet(self, analysis):
        """添加数据包到处理队列"""
        # 构建存储数据结构
        db_record = {
            'src_mac': analysis['metadata'].get('src_mac'),
            'dst_mac': analysis['metadata'].get('dst_mac'),
            'src_ip': analysis['metadata'].get('src_ip'),
            'dst_ip': analysis['metadata'].get('dst_ip'),
            'src_port': analysis['metadata'].get('src_port'),
            'dst_port': analysis['metadata'].get('dst_port'),
            'protocol': analysis.get('layer_hierarchy', '').split('/')[-1],
            'details': self._extract_details(analysis),
            'raw_hex': analysis.get('payload')
        }

        self.batch_queue.put(db_record)

    def _extract_details(self, analysis):
        """提取协议特定信息"""
        details = {}
        layers = analysis.get('layers', {})

        # HTTP协议详情
        if 'HTTP' in layers:
            http = layers['HTTP']
            details['http'] = {
                'type': http.get('type'),
                'method': http.get('method'),
                'path': http.get('path'),
                'status': http.get('status_code'),
                'host': http.get('host')
            }

        # DNS协议详情
        if 'DNS' in layers:
            dns = layers['DNS']
            details['dns'] = {
                'transaction_id': dns.get('transaction_id'),
                'qr': dns.get('qr'),
                'questions': dns.get('questions', []),
                'answers': dns.get('answers', [])
            }

        # ICMP协议详情
        if 'ICMP' in analysis.get('layer_hierarchy', ''):
            details['icmp'] = {
                'type': analysis['metadata'].get('icmp_type'),
                'code': analysis['metadata'].get('icmp_code')
            }

        return details

    def cleanup_old_records(self, days=30):
        """清理过期记录"""
        cutoff = datetime.now().timestamp() - days * 86400
        with self.lock, sqlite3.connect(self.db_name) as conn:
            conn.execute("""
                DELETE FROM packets 
                WHERE timestamp < ?
            """, (datetime.fromtimestamp(cutoff).isoformat(),))
            conn.commit()
