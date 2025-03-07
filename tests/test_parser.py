import unittest
from core.parser import EnhancedProtocolParser
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.tls.record import TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.layers.tls.extensions import ServerName, TLS_Ext_SupportedGroups

class TestEnhancedProtocolParser(unittest.TestCase):
    def setUp(self):

        self.parser = EnhancedProtocolParser()
        self.dns_packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                          IP(src="192.168.1.1", dst="8.8.8.8") / \
                          UDP(sport=12345, dport=53) / \
                          DNS(qd=DNSQR(qname="example.com"))

    def test_dns_query_parsing(self):  # 确保方法以test_开头
        result = self.parser.parse_packet(self.dns_packet)

        # 验证元数据
        self.assertEqual(result['metadata']['src_mac'], "00:11:22:33:44:55")
        self.assertEqual(result['metadata']['dst_mac'], "66:77:88:99:aa:bb")
        self.assertEqual(result['metadata']['src_ip'], "192.168.1.1")
        self.assertEqual(result['metadata']['dst_ip'], "8.8.8.8")
        self.assertEqual(result['metadata']['src_port'], 12345)
        self.assertEqual(result['metadata']['dst_port'], 53)

        # 验证协议层级
        self.assertEqual(result['layer_hierarchy'], "Ethernet/IPv4/UDP/DNS")

        # 验证DNS解析
        dns_info = result['layers']['DNS']
        self.assertEqual(dns_info['questions'][0]['name'], 'example.com.')
        self.assertEqual(dns_info['questions'][0]['type'], 1)



if __name__ == '__main__':
    unittest.main()

