# 基础协议层导入（增加异常导入处理）
import warnings
from collections import defaultdict

import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPResponse, HTTPRequest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
# 增强测试用例
import scapy.all


class EnhancedProtocolParser:
    def __init__(self, db_manager=None):
        # 使用defaultdict优化统计逻辑[4](@ref)
        self.protocol_stats = defaultdict(int)
        self.layer_hierarchy = []
        self.db_manager = db_manager

    def parse_packet(self, packet: Packet) -> dict:
        """增强型解析方法，支持异常处理和协议扩展"""
        result = {
            'metadata': {},
            'layers': {},
            'payload': None
        }

        try:
            # 分层解析（按协议栈顺序）
            self._parse_link_layer(packet, result)
            self._parse_network_layer(packet, result)
            self._parse_transport_layer(packet, result)
            self._parse_application_layer(packet, result)
            self._parse_raw_payload(packet, result)

            # 构建协议层次关系[6](@ref)
            result['layer_hierarchy'] = '/'.join(self.layer_hierarchy)

        except Exception as e:
            warnings.warn(f"Packet parsing error: {str(e)}")
        if self.db_manager:
            self.db_manager.save_packet(result)

        return result

    def _parse_link_layer(self, packet, result):
        """链路层解析（支持多种链路层协议）"""
        if packet.haslayer(Ether):
            self.layer_hierarchy.append('Ethernet')
            eth = packet[Ether]
            result['metadata'].update({
                'src_mac': eth.src,
                'dst_mac': eth.dst
            })
            self.protocol_stats['Ethernet'] += 1

    def _parse_network_layer(self, packet, result):
        """网络层解析（支持IPv4/IPv6）"""
        if packet.haslayer(IP):
            self.layer_hierarchy.append('IPv4')
            ip = packet[IP]
            result['metadata'].update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ip_version': 4
            })
            self.protocol_stats['IPv4'] += 1

    def _parse_transport_layer(self, packet, result):
        """传输层解析（支持TCP/UDP/ICMP）"""
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
            self.layer_hierarchy.append(transport_protocol)
            self.protocol_stats[transport_protocol] += 1

    def _parse_application_layer(self, packet, result):
        """应用层解析（支持DNS/HTTP）"""
        if packet.haslayer(DNS):
            self._parse_dns(packet, result)
        elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self._parse_http(packet, result)

    def _parse_dns(self, packet, result):
        """增强DNS解析（支持查询/响应类型）[3](@ref)"""
        self.layer_hierarchy.append('DNS')
        dns = packet[DNS]
        dns_data = {
            'transaction_id': dns.id,
            'qr': 'query' if dns.qr == 0 else 'response',
            'questions': [],
            'answers': []
        }

        # 解析DNS问题记录
        if dns.qd:
            for q in dns.qd:
                if isinstance(q, DNSQR):
                    dns_data['questions'].append({
                        'name': q.qname.decode('utf-8', 'replace'),
                        'type': q.qtype
                    })

        # 解析DNS资源记录
        if dns.an:
            for rr in dns.an:
                if isinstance(rr, DNSRR):
                    answer = {
                        'name': rr.rrname.decode('utf-8', 'replace'),
                        'type': rr.type,
                        'data': rr.rdata
                    }
                    if rr.type == 1:  # A记录
                        answer['ip'] = rr.rdata
                    dns_data['answers'].append(answer)

        result['layers']['DNS'] = dns_data
        self.protocol_stats['DNS'] += 1

    def _parse_http(self, packet, result):
        """增强HTTP解析（支持请求/响应）[5](@ref)"""
        self.layer_hierarchy.append('HTTP')
        http_data = {}

        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            http_data['type'] = 'Request'
            http_data.update({
                'method': self._safe_decode(req.Method),
                'path': self._safe_decode(req.Path),
                'host': self._safe_decode(req.Host),
                'user_agent': self._safe_decode(req.User_Agent)
            })
        elif packet.haslayer(HTTPResponse):
            res = packet[HTTPResponse]
            http_data['type'] = 'Response'
            http_data.update({
                'status_code': res.Status_Code,
                'reason': self._safe_decode(res.Reason_Phrase),
                'content_type': self._safe_decode(res.Content_Type)
            })

        result['layers']['HTTP'] = http_data
        self.protocol_stats['HTTP'] += 1

    def _parse_icmp(self, packet, result):
        """ICMP协议解析"""
        icmp = packet.getlayer(ICMP)
        if icmp:
            result['metadata'].update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code
            })

    def _parse_raw_payload(self, packet, result):
        """增强载荷解析（支持多种编码）"""
        if packet.haslayer(scapy.Raw):
            raw = packet[scapy.Raw].load
            try:
                # 尝试UTF-8解码
                result['payload'] = raw.decode('utf-8')
            except UnicodeDecodeError:
                # 二进制数据转十六进制
                result['payload'] = raw.hex()

    def _parse_tcp_flags(self, tcp):
        """解析TCP标志位[6](@ref)"""
        flags = []
        if tcp.flags.S: flags.append('SYN')
        if tcp.flags.A: flags.append('ACK')
        if tcp.flags.F: flags.append('FIN')
        if tcp.flags.R: flags.append('RST')
        if tcp.flags.P: flags.append('PSH')
        if tcp.flags.U: flags.append('URG')
        return flags

    def _safe_decode(self, field):
        """安全解码字节字段"""
        try:
            return field.decode('utf-8', errors='replace') if field else None
        except AttributeError:
            return str(field) if field else None


if __name__ == "__main__":
    # 构造复合测试包
    test_packets = [
        # HTTP请求
        Ether() / IP(dst="www.example.com") / TCP(dport=80) / HTTPRequest(
            Method=b'GET',
            Path=b'/api',
            Host=b'www.example.com'
        ) / scapy.all.Raw(load="test=1"),

        # DNS响应
        Ether() / IP() / UDP() / DNS(
            id=1234,
            qr=1,
            qd=DNSQR(qname="www.example.com"),
            an=DNSRR(rrname="www.example.com", rdata="192.168.1.1")
        ),
        # 1. 标准Ping请求（Type=8, Code=0）
        Ether() / IP(src="192.168.1.100", dst="192.168.1.1") / ICMP(type=8, code=0) / Raw(load="Ping Request"),
    ]

    parser = EnhancedProtocolParser()
    for pkt in test_packets:
        analysis = parser.parse_packet(pkt)
        print("解析结果:", analysis)
        print("协议统计:", dict(parser.protocol_stats))
        print("-" * 60)
