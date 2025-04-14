import binascii
import warnings
from collections import defaultdict
import cryptography
import scapy.all as scapy
from _socket import AF_INET6, AF_INET
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPResponse, HTTPRequest,HTTP
from scapy.layers.inet6 import IPv6
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.extensions import ServerName
from scapy.layers.tls.record import TLS
from scapy.packet import Packet
from scapy.pton_ntop import inet_ntop
from core import TLSparser


class EnhancedProtocolParser:
    def __init__(self, db_manager=None):
        self.protocol_stats = defaultdict(int)
        self.layer_hierarchy = []
        self.db_manager = db_manager
        self.tls_parser = TLSparser

    def parse_packet(self, packet: Packet) -> dict:
        result = {
            'metadata': {'packet_size': len(packet)},
            'details': {},
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
            result['details']['ARP'] = arp_data
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
        elif packet.haslayer(IPv6):
            network_proto = 'IPv6'
            ipv6 = packet[IPv6]
            result['metadata'].update({
                'src_ip': ipv6.src,
                'dst_ip': ipv6.dst,
                'ip_version': 6,
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
            self._parse_tls(packet, result)  # 触发深度解析
            self.layer_hierarchy.append('HTTPS')
            self.protocol_stats['HTTPS'] += 1
            return  # TLS 解析后优先返回

        # 特征识别优先于端口识别
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self._parse_http(packet, result)
            return  # HTTP 解析后直接返回

        if packet.haslayer(DNS):
            self.layer_hierarchy.append('DNS')
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
        result['details']['HTTP'] = http_info
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
        """集成新 TLS 解析器的增强解析方法"""
        result.setdefault('layers', {})
        tls_data = result['layers'].setdefault('TLS', {})

        try:
            # 确保存在Raw层以获取原始数据
            if not packet.haslayer(scapy.Raw):
                return

            raw_tls = packet[scapy.Raw].load
            tls_record = self.tls_parser.parse_record(raw_tls)

            if not tls_record:
                return

            # 转换解析结果为字典格式
            tls_details = {
                'protocol_version': tls_record.version,
                'handshake': {
                    'type': 'ClientHello' if tls_record.handshake.type == 1 else 'ServerHello',
                    'ciphers': tls_record.handshake.ciphers,
                    'extensions': [
                        {
                            'type_id': ext['type'],
                            'type_name': self.tls_parser.extensions.get(ext['type'], 'unknown'),
                            'data': ext.get('sni', ext.get('protocols', ext['data']))
                        } for ext in tls_record.handshake.extensions
                    ],
                    'random': tls_record.handshake.random,
                    'session_id': tls_record.handshake.session_id
                },
                'security_analysis': self._analyze_tls_security(tls_record)
            }

            # 更新到details字段
            result['details']['tls'] = tls_details

        except Exception as e:
            error_msg = self._format_exception(e)
            tls_data['error'] = error_msg
            warnings.warn(f"深度 TLS 解析错误: {error_msg}")

    def _analyze_tls_security(self, tls_record):
        """新增 TLS 安全评估方法"""
        findings = []

        # 检查弱密码套件
        weak_ciphers = {'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'}
        used_weak = [c for c in tls_record.handshake.ciphers if c in weak_ciphers]
        if used_weak:
            findings.append(f"发现弱加密套件: {', '.join(used_weak)}")

        # 检查关键扩展缺失
        required_ext = {'supported_versions', 'signature_algorithms'}
        present_ext = {e['type'] for e in tls_record.handshake.extensions}
        missing_ext = required_ext - present_ext
        if missing_ext:
            findings.append(f"缺少必要扩展: {', '.join(missing_ext)}")

        return findings if findings else ['符合现代安全标准']

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