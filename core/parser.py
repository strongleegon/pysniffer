import unittest
import warnings
from collections import defaultdict
import scapy.all as scapy
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPResponse, HTTPRequest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.extensions import ServerName, TLS_Ext_SupportedGroups
from scapy.packet import Packet, Raw

class EnhancedProtocolParser:
    def __init__(self, db_manager=None):
        self.protocol_stats = defaultdict(int)
        self.layer_hierarchy = []
        self.db_manager = db_manager

    def parse_packet(self, packet: Packet) -> dict:
        result = {
            'metadata': {},
            'layers': {},
            'payload': None,
            'error': None
        }
        self.layer_hierarchy = []

        try:
            self._parse_link_layer(packet, result)
            self._parse_network_layer(packet, result)
            self._parse_transport_layer(packet, result)
            self._parse_application_layer(packet, result)
            self._parse_raw_payload(packet, result)

            result['layer_hierarchy'] = '/'.join(self.layer_hierarchy)
        except Exception as e:
            print("aaa", e)
            result['error'] = str(e)
            warnings.warn(f"Packet parsing error: {str(e)}")

        return result

    def _parse_link_layer(self, packet, result):
        if packet.haslayer(Ether):
            self.layer_hierarchy.append('Ethernet')
            eth = packet[Ether]
            result['metadata'].update({
                'src_mac': eth.src,
                'dst_mac': eth.dst
            })
            self.protocol_stats['Ethernet'] += 1

    def _parse_network_layer(self, packet, result):
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
        if packet.haslayer(TLS):
            self._parse_tls(packet, result)
            # 检查是否为标准HTTPS端口或包含SNI
            if (packet.haslayer(TCP) and packet[TCP].dport == 443) or \
                    result['layers'].get('TLS', {}).get('sni'):
                self.layer_hierarchy.append('HTTPS')
                self.protocol_stats['HTTPS'] += 1
        elif packet.haslayer(DNS):
            self._parse_dns(packet, result)
        elif packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            self._parse_http(packet, result)

    def _parse_dns(self, packet, result):
        self.layer_hierarchy.append('DNS')
        self.protocol_stats['DNS'] += 1

        dns = packet[DNS]
        dns_data = {
            'transaction_id': dns.id,
            'qr': 'query' if dns.qr == 0 else 'response',
            'questions': [],
            'answers': []
        }

        if dns.qd:
            for q in dns.qd:
                if isinstance(q, DNSQR):
                    dns_data['questions'].append({
                        'name': q.qname.decode('utf-8', 'replace'),
                        'type': q.qtype
                    })

        if dns.an:
            for rr in dns.an:
                if isinstance(rr, DNSRR):
                    dns_data['answers'].append({
                        'name': rr.rrname.decode('utf-8', 'replace'),
                        'type': rr.type,
                        'data': rr.rdata
                    })

        result['layers']['DNS'] = dns_data

    def _parse_http(self, packet, result):
        self.layer_hierarchy.append('HTTP')
        self.protocol_stats['HTTP'] += 1

        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            result['layers']['HTTP'] = {
                'type': 'Request',
                'method': http.Method.decode('utf-8', 'replace'),
                'path': http.Path.decode('utf-8', 'replace'),
                'host': http.Host.decode('utf-8', 'replace')
            }
        elif packet.haslayer(HTTPResponse):
            http = packet[HTTPResponse]
            result['layers']['HTTP'] = {
                'type': 'Response',
                'status_code': http.Status_Code.decode('utf-8', 'replace'),
                'reason': http.Reason_Phrase.decode('utf-8', 'replace')
            }

    def _parse_icmp(self, packet, result):
        icmp = packet.getlayer(ICMP)
        if icmp:
            result['metadata'].update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code
            })

    def _parse_raw_payload(self, packet, result):
        if packet.haslayer(scapy.Raw):
            raw = packet[scapy.Raw].load
            for encoding in ['utf-8', 'latin-1', 'gbk', 'iso-8859-1']:  # 常见编码尝试顺序
                try:
                    result['payload'] = raw.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue
            else:  # 所有编码均失败时转为十六进制
                result['payload'] = raw.hex()

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
        try:
            tls_layer = packet[TLS]
            while tls_layer:
                tls_data = self._parse_tls_layer(tls_layer)
                result["layers"]["TLS"] = tls_data
                tls_layer = tls_layer.payload
        except Exception as e:
            print('Exc')
            print("Exception", e)
            result["error"] = f"TLS parsing error: {str(e)}"
            self.protocol_stats["Errors"] += 1

    def _process_tls_record(self, tls_layer, tls_data):
        if tls_layer.haslayer(TLSClientHello):
            ch = tls_layer[TLSClientHello]
            tls_data['handshake_stage'] = 'ClientHello'
            tls_data['version'] = self._parse_tls_version(ch.version)
            self._parse_client_hello_extensions(ch, tls_data)

        elif tls_layer.haslayer(TLSServerHello):
            sh = tls_layer[TLSServerHello]
            tls_data['handshake_stage'] = 'ServerHello'
            tls_data['version'] = self._parse_tls_version(sh.version)
            tls_data['selected_cipher'] = self._parse_cipher(sh.cipher)

    def _parse_tls_layer(self, tls_layer):
        tls_data = {}
        try:
            # 解析 TLS 版本
            if hasattr(tls_layer, "version"):
                tls_data["version"] = tls_layer.version

            # 解析握手协议
            if hasattr(tls_layer, "msg"):
                for msg in tls_layer.msg:
                    if msg.name == "ClientHello":
                        tls_data["handshake_type"] = "ClientHello"
                        # 提取 SNI
                        if hasattr(msg, "extensions"):
                            for ext in msg.extensions:
                                if ext.type == 0:
                                    tls_data["sni"] = ext.server_name
                    elif msg.name == "ServerHello":
                        tls_data["handshake_type"] = "ServerHello"

            # 解析加密套件
            if hasattr(tls_layer, "cipher_suites"):
                tls_data["ciphers"] = [cipher.name for cipher in tls_layer.cipher_suites]

        except Exception as e:
            tls_data["error"] = f"TLS layer error: {str(e)}"
        return tls_data

    def _parse_client_hello_extensions(self, ch, tls_data):
        def _parse_client_hello_extensions(self, ch, tls_data):
            if hasattr(ch, 'extensions'):
                for ext in ch.extensions:
                    if isinstance(ext, ServerName):
                        try:
                            tls_data['sni'] = ext.servername.decode("utf-8", "replace")
                        except UnicodeDecodeError as e:
                            print('UnicodeDecodeError')
                            print("UnicodeDecodeError", e)
                            tls_data['sni'] = ext.servername.hex()
                        break  # 只要第一个SNI

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


