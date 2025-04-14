import unittest

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP,TCP
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTPResponse, HTTPRequest,HTTP
from core.parser import EnhancedProtocolParser

class TestEnhancedProtocolParser(unittest.TestCase):
    def setUp(self):

        self.parser = EnhancedProtocolParser()
        self.dns_packet = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
                          IP(src="192.168.1.1", dst="8.8.8.8") / \
                          UDP(sport=12345, dport=53) / \
                          DNS(qd=DNSQR(qname="example.com"))
        # 构造HTTP测试包
        self.http_packet = Ether(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff") / \
                           IP(src="10.0.0.1", dst="203.0.113.5") / \
                           TCP(sport=54321, dport=80, flags="PA") / \
                           HTTP() / \
                           HTTPRequest(
                               Method=b"GET",
                               Path=b"/api/v1/data",
                               Host=b"example.com",
                               User_Agent=b"TestClient"
                           )

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
        dns_info = result['details']['dns']
        self.assertEqual(dns_info['questions'][0]['name'], 'example.com.')
        self.assertEqual(dns_info['questions'][0]['type'], 1)

    def test_http_parsing(self):
        result = self.parser.parse_packet(self.http_packet)

        # 验证元数据
        self.assertEqual(result['metadata']['src_mac'], "11:22:33:44:55:66")
        self.assertEqual(result['metadata']['dst_mac'], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result['metadata']['src_ip'], "10.0.0.1")
        self.assertEqual(result['metadata']['dst_ip'], "203.0.113.5")
        self.assertEqual(result['metadata']['src_port'], 54321)
        self.assertEqual(result['metadata']['dst_port'], 80)

        # 验证协议层级

        # 验证HTTP详情
        http_info = result['details']['HTTP']
        self.assertEqual(http_info['method'], 'GET')
        self.assertEqual(http_info['path'], '/api/v1/data')
        self.assertEqual(http_info['host'], 'example.com')

if __name__ == '__main__':
    unittest.main()

