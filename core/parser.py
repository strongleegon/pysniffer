import binascii
import warnings
from collections import defaultdict

import scapy.all as scapy
from _socket import AF_INET6, AF_INET
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPResponse, HTTPRequest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.extensions import ServerName
from scapy.layers.tls.record import TLS
from scapy.packet import Packet
from scapy.pton_ntop import inet_ntop


class EnhancedProtocolParser:
    def __init__(self, db_manager=None):
        self.protocol_stats = defaultdict(int)
        self.layer_hierarchy = []
        self.db_manager = db_manager

    def parse_packet(self, packet: Packet) -> dict:
        result = {
            'metadata': {'packet_size': len(packet)},
            'layers': {},
            'payload': None,
            'error': None,
            'raw_packet': bytes(packet)
        }
        self.layer_hierarchy = []

        try:
            self._parse_link_layer(packet, result)
            self._parse_network_layer(packet, result)
            self._parse_transport_layer(packet, result)
            self._parse_application_layer(packet, result)
            self._parse_raw_payload(packet, result)
            self._calculate_layer_sizes(packet, result)

            result['layer_hierarchy'] = '/'.join(self.layer_hierarchy)
        except Exception as e:
            error_msg = self._format_exception(e)
            result['error'] = error_msg
            warnings.warn(f"Packet parsing error: {error_msg}")
        return result

    def _format_exception(self, e: Exception) -> str:
        """改进后的异常信息格式化，处理嵌套字节数据"""

        def process_bytes(data):
            try:
                return binascii.hexlify(data).decode('utf-8')
            except Exception:
                return repr(data)

        parts = []
        for arg in e.args:
            if isinstance(arg, bytes):
                parts.append(process_bytes(arg))
            elif isinstance(arg, str):
                parts.append(arg)
            else:
                parts.append(str(arg))
        return ": ".join(parts)

    def _parse_link_layer(self, packet, result):
        if packet.haslayer(Ether):
            self.layer_hierarchy.append('Ethernet')
            eth = packet[Ether]
            result['metadata'].update({
                'src_mac': eth.src,
                'dst_mac': eth.dst
            })
            self.protocol_stats['Ethernet'] += 1
            # 新增ARP解析
        if packet.haslayer(ARP):
            self.layer_hierarchy.append('ARP')
            arp = packet[ARP]
            op_map = {1: 'request', 2: 'response'}
            arp_data = {
                'operation': op_map.get(arp.op, f'unknown ({arp.op})'),
                'sender_mac': arp.hwsrc,
                'sender_ip': arp.psrc,
                'target_mac': arp.hwdst,
                'target_ip': arp.pdst
            }
            result['layers']['ARP'] = arp_data
            self.protocol_stats['ARP'] += 1
            # 更新metadata，避免与Ethernet字段冲突
            result['metadata'].update({
                'arp_sender_mac': arp.hwsrc,
                'arp_sender_ip': arp.psrc,
                'arp_target_mac': arp.hwdst,
                'arp_target_ip': arp.pdst,
                'arp_op': arp.op
            })

    def _parse_network_layer(self, packet, result):
        """改进后的网络层解析"""
        network_proto = None
        if packet.haslayer(IP):
            network_proto = 'IPv4'
            ip = packet[IP]
            result['metadata'].update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ip_version': 4
            })

        if network_proto:
            self.layer_hierarchy.append(network_proto)
            self.protocol_stats[network_proto] += 1
            result['metadata']['network_protocol'] = network_proto  # 明确记录网络层协议

    def _parse_transport_layer(self, packet, result):
        transport_protocol = None
        if packet.haslayer(TCP):
            transport_protocol = 'TCP'
            tcp = packet[TCP]
            result['metadata'].update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'flags': self._parse_tcp_flags(tcp)
            })
        elif packet.haslayer(UDP):
            transport_protocol = 'UDP'
            udp = packet[UDP]
            result['metadata'].update({
                'src_port': udp.sport,
                'dst_port': udp.dport
            })
        elif packet.haslayer(ICMP):
            self._parse_icmp(packet, result)
            transport_protocol = 'ICMP'

        if transport_protocol:
            result['metadata']['transport_protocol'] = transport_protocol
            self.layer_hierarchy.append(transport_protocol)
            self.protocol_stats[transport_protocol] += 1

    def _parse_application_layer(self, packet, result):
        # 扩展协议识别范围
        PORT_PROTOCOL_MAP = {
            21: 'FTP', 25: 'SMTP', 110: 'POP3',
            143: 'IMAP', 53: 'DNS', 80: 'HTTP',
            443: 'HTTPS', 5060: 'SIP'
        }

        # 优先检查已知应用层特征
        if packet.haslayer(TCP) and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            try:
                # 验证是否为有效的 TLS 握手（ContentType=0x16）
                if bytes(packet[TCP].payload).startswith(b'\x16'):
                    self._parse_tls(packet, result)
            except Exception as e:
                result['error'] = f"TLS 检测失败: {self._format_exception(e)}"

        # 特征识别优先于端口识别
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self._parse_http(packet, result)
            return  # HTTP 解析后直接返回

        if packet.haslayer(DNS):
            self._parse_dns(packet, result)
            return  # DNS 解析后直接返回

        # 动态端口协议识别（支持源/目标端口）
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        if transport_layer:
            # 同时检查源端口和目标端口
            for port in [transport_layer.sport, transport_layer.dport]:
                proto = PORT_PROTOCOL_MAP.get(port)
                if proto and proto not in self.layer_hierarchy:
                    self.layer_hierarchy.append(proto)
                    self.protocol_stats[proto] += 1
                    result['layers'][proto] = {'port': port}  # 记录端口信息
                    break  # 识别到即停止

    def _parse_dns(self, packet, result):
        dns = packet.getlayer(DNS)
        if not dns:
            return
        result.setdefault('details', {})

        dns_details = {
            'qr': 'query' if dns.qr == 0 else 'response',
            'questions': [],
            'answers': []
        }

    # 处理查询部分
        for q in dns.qd:
            question = {
                'name': q.qname.decode('utf-8', errors='replace'),
                'type': q.qtype
            }
            dns_details['questions'].append(question)

    # 处理回答部分
        for answer in dns.an:
            answer_data = {
                'type': int(answer.type),
                'name': answer.rrname.decode('utf-8', errors='replace'),
                'data': self._decode_dns_rdata(answer)  # 使用专用解码方法
            }
            dns_details['answers'].append(answer_data)

        result['details']['dns'] = dns_details

    def _decode_dns_rdata(self, answer):
        """统一处理DNS响应数据的解码"""
        try:
            if answer.type == 1:  # A记录
                return inet_ntop(AF_INET, answer.rdata) if len(answer.rdata) == 4 else answer.rdata.hex()
            elif answer.type == 28:  # AAAA记录
                return inet_ntop(AF_INET6, answer.rdata) if len(answer.rdata) == 16 else answer.rdata.hex()
            else:
                return answer.rdata.decode('utf-8', errors='replace')
        except Exception as e:
            return f"DecodeError: {str(e)}"

    def _parse_http(self, packet, result):
        result.setdefault('layers', {})  # <--- 新增
        result['layers'].setdefault('HTTP', {})  # <--- 新增
        http_info = {'type': 'Unknown'}
        try:
            if packet.haslayer(HTTPRequest):
                http = packet[HTTPRequest]
                http_info.update({
                    'type': 'Request',
                    'method': getattr(http, 'Method', b'').decode('utf-8', 'replace'),
                    'path': getattr(http, 'Path', b'').decode('utf-8', 'replace'),
                    'host': getattr(http, 'Host', b'').decode('utf-8', 'replace')
                })
            elif packet.haslayer(HTTPResponse):
                http = packet[HTTPResponse]
                http_info.update({
                    'type': 'Response',
                    'status': getattr(http, 'Status_Code', b'').decode('utf-8', 'replace'),
                    'reason': getattr(http, 'Reason_Phrase', b'').decode('utf-8', 'replace')
                })
        except Exception as e:
            http_info['error'] = str(e)

        result['layers']['HTTP'] = http_info
        self.layer_hierarchy.append('HTTP')
        self.protocol_stats['HTTP'] += 1

    def _parse_icmp(self, packet, result):
        icmp = packet.getlayer(ICMP)
        if icmp:
            result['metadata'].update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code
            })

    def _parse_raw_payload(self, packet, result):
        """直接存储原始二进制数据"""
        if packet.haslayer(scapy.Raw):
            raw = packet[scapy.Raw].load
            result['payload'] = raw  # 存储bytes类型数据

    def _parse_tcp_flags(self, tcp):
        flags = []
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.P: flags.append('PSH')
        if tcp.flags.U: flags.append('URG')
        return flags

    def _parse_tls(self, packet, result):
        """改进后的 TLS 解析，增加有效性检查"""
        result.setdefault('layers', {})
        tls_data = result['layers'].setdefault('TLS', {})

        # 验证是否为有效的 TLS 记录
        if not packet.haslayer(TLS):
            return

        try:
            tls_layer = packet[TLS]
            # 检查 TLS 记录头长度
            if len(tls_layer) < 5:  # 至少包含 ContentType(1) + Version(2) + Length(2)
                raise ValueError("Invalid TLS header length")

            # 解析每个 TLS 记录
            while tls_layer:
                self._parse_tls_record(tls_layer, tls_data)
                tls_layer = tls_layer.payload

        except Exception as e:
            error_msg = self._format_exception(e)
            tls_data['error'] = error_msg
            warnings.warn(f"TLS 解析错误: {error_msg}")

    def _parse_tls_record(self, tls_layer, tls_data):
        """安全解析单个 TLS 记录"""
        try:
            # 安全获取字段
            content_type = getattr(tls_layer, 'type', 0)
            version = getattr(tls_layer, 'version', 0)
            length = getattr(tls_layer, 'len', 0)

            # 记录基本信息
            record_info = {
                'content_type': content_type,
                'version': self._parse_tls_version(version),
                'length': length
            }
            tls_data.setdefault('records', []).append(record_info)

            # 仅解析 Handshake 类型（如 ClientHello）
            if content_type == 22:  # 0x16 是 Handshake
                self._parse_handshake(tls_layer, record_info)

        except Exception as e:
            record_info['error'] = self._format_exception(e)

    def _parse_handshake(self, tls_layer, record_info):
        """解析 TLS Handshake 消息"""
        try:
            handshake = tls_layer.msg[0]  # 假设第一个消息是 Handshake
            msg_type = getattr(handshake, 'msg_type', 0)
            record_info['handshake_type'] = msg_type

            # 仅处理 ClientHello (1) 和 ServerHello (2)
            if msg_type not in [1, 2]:
                return

            # 安全获取版本和随机数
            record_info.update({
                'version': self._parse_tls_version(getattr(handshake, 'version', 0)),
                'random': binascii.hexlify(getattr(handshake, 'random', b'')).decode(),
            })

            # 解析 ClientHello 的扩展
            if msg_type == 1:  # ClientHello
                self._parse_client_hello(handshake, record_info)

        except IndexError:
            raise ValueError("Missing Handshake message in TLS record")
        except Exception as e:
            raise ValueError(f"Handshake 解析失败: {self._format_exception(e)}")

    def _parse_tls_layer(self, tls_layer, tls_data):
        """增强的TLS记录解析"""
        try:
            # 安全获取版本信息
            version = getattr(tls_layer, 'version', None)
            if version:
                tls_data['version'] = self._parse_tls_version(version)

            # 安全解析消息类型
            for msg in getattr(tls_layer, 'msg', []):
                try:
                    msg_type = getattr(msg, 'name', 'unknown')
                    if msg_type == 'ClientHello':
                        tls_data['handshake_type'] = msg_type
                        if hasattr(msg, 'extensions'):
                            self._parse_client_hello(msg, tls_data)
                    elif msg_type == 'ServerHello':
                        tls_data['handshake_type'] = msg_type
                except Exception as e:
                    tls_data.setdefault('errors', []).append(
                        f"消息解析错误: {self._format_exception(e)}"
                    )
        except Exception as e:
            raise ValueError(f"TLS记录解析失败: {self._format_exception(e)}")

    def _parse_client_hello(self, handshake, record_info):
        """解析 ClientHello 消息的扩展"""
        try:
            # 安全获取扩展列表
            extensions = getattr(handshake, 'extensions', [])
            if not extensions:
                return

            # 解析每个扩展
            ext_info = []
            for ext in extensions:
                ext_data = {'type': ext.type}
                if isinstance(ext, ServerName):
                    ext_data['server_name'] = self._parse_server_name(ext)
                ext_info.append(ext_data)

            record_info['extensions'] = ext_info

        except Exception as e:
            raise ValueError(f"ClientHello 扩展解析失败: {self._format_exception(e)}")

    def _parse_server_name(self, ext):
        """安全解析 SNI 信息"""
        try:
            name = getattr(ext, 'servername', '')
            if isinstance(name, bytes):
                return name.decode('utf-8', errors='replace')
            return str(name)
        except AttributeError:
            return "SNI Unavailable"
    def _parse_tls_version(self, version_code):
        versions = {
            0x0304: "TLS 1.3",
            0x0303: "TLS 1.2",
            0x0302: "TLS 1.1",
            0x0301: "TLS 1.0",
            0x0300: "SSL 3.0"
        }
        return versions.get(version_code, f"Unknown (0x{version_code:04x})")

    def _parse_cipher(self, cipher_code):
        ciphers = {
            0x1301: "TLS_AES_128_GCM_SHA256",
            0x1302: "TLS_AES_256_GCM_SHA384",
            0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        }
        return ciphers.get(cipher_code, f"Unidentified (0x{cipher_code:04x})")

    def _calculate_layer_sizes(self, packet, result):
        layer_sizes = {}
        current_layer = packet

        while current_layer:
            layer_name = current_layer.name
            payload = current_layer.payload

            # 处理TCP层
            if isinstance(current_layer, TCP):
                try:
                    # 确保dataofs的有效性（TCP头部长度以4字节为单位）
                    dataofs = current_layer.dataofs
                    if dataofs < 5 or dataofs > 15:  # 根据RFC 793规范，dataofs范围应为5-15
                        dataofs = 5  # 使用最小有效值作为默认值
                    header_length = dataofs * 4
                except AttributeError:
                    header_length = 20  # 默认20字节
                layer_sizes['TCP'] = {
                    'header_size': header_length,
                    'payload_size': len(payload)
                }

            # 处理UDP层
            elif isinstance(current_layer, UDP):
                layer_sizes['UDP'] = {
                    'header_size': 8,
                    'payload_size': len(payload)
                }

            # 处理其他层
            else:
                header_size = len(current_layer) - len(payload) if payload else len(current_layer)
                layer_sizes[layer_name] = {
                    'header_size': header_size,
                    'payload_size': len(payload) if payload else 0
                }

            current_layer = payload

        result['layer_sizes'] = layer_sizes