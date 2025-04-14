import unittest
from core.TLSparser import TLSParser
from core.parser import EnhancedProtocolParser
import unittest
from io import BytesIO


class TestTLSParser(unittest.TestCase):
    def setUp(self):
        self.parser = TLSParser()

    def build_client_hello(self):
        # 构造一个模拟的 TLS Client Hello 消息
        handshake_type = 0x01  # ClientHello

        # 版本 TLS 1.2 (0x0303)
        version = 0x0303

        # 随机数 (32字节)
        random = bytes.fromhex('''
            000102030405060708090a0b0c0d0e0f 
            101112131415161718191a1b1c1d1e1f
        ''')

        # Session ID (0字节长度)
        session_id = b'\x00'

        # 密码套件 (2个示例套件)
        ciphers = bytes.fromhex('1301c02b')  # TLS_AES_128_GCM_SHA256 和 TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        cipher_len = len(ciphers).to_bytes(2, 'big')

        # 压缩方法 (1个空压缩)
        compression = b'\x01\x00'

        # 扩展部分
        extensions = BytesIO()

        # SNI 扩展 (服务器名称: example.com)
        sni = bytes.fromhex('0000'  # 扩展类型 0x0000
                            '000d'  # 扩展长度 13
                            '000b'  # 服务器名称列表长度 11
                            '00'  # 名称类型 0 (host_name)
                            '0008'  # 名称长度 8
                            ) + b'example.'
        extensions.write(sni)

        # 支持的组扩展 (示例)
        supported_groups = bytes.fromhex('000a'  # 扩展类型 0x000a
                                         '0004'  # 扩展长度 4
                                         '0002'  # 组列表长度 2
                                         '001d'  # x25519
                                         )
        extensions.write(supported_groups)

        ext_data = extensions.getvalue()
        ext_len = len(ext_data).to_bytes(2, 'big')

        # 组装握手协议
        handshake = BytesIO()
        handshake.write(bytes([handshake_type]))  # 类型
        handshake.write(b'\x00\x00\x00')  # 长度占位符

        handshake.write(version.to_bytes(2, 'big'))  # 版本
        handshake.write(random)  # 随机数
        handshake.write(session_id)  # Session ID
        handshake.write(cipher_len)  # 密码套件长度
        handshake.write(ciphers)  # 密码套件
        handshake.write(compression)  # 压缩方法
        handshake.write(ext_len)  # 扩展长度
        handshake.write(ext_data)  # 扩展数据

        # 计算握手协议长度并更新
        hs_data = handshake.getvalue()
        hs_len = len(hs_data) - 4  # 减去类型(1字节)和长度字段(3字节)
        hs_data = bytes([handshake_type]) + (hs_len).to_bytes(3, 'big') + hs_data[4:]

        # 组装 TLS 记录层
        record = BytesIO()
        record.write(bytes([0x16]))  # 类型: Handshake (22)
        record.write(b'\x03\x03')  # 版本: TLS 1.2
        record.write(len(hs_data).to_bytes(2, 'big'))  # 长度
        record.write(hs_data)  # 握手协议数据

        return record.getvalue()

    def test_client_hello_parsing(self):
        data = self.build_client_hello()
        result = self.parser.parse_record(data)

        # 验证记录层
        self.assertEqual(result.type, 0x16)
        self.assertEqual(result.version, 'TLS 1.2')
        self.assertGreater(result.length, 0)

        # 验证握手协议
        hs = result.handshake
        self.assertEqual(hs.type, 0x01)
        self.assertEqual(hs.version, 'TLS 1.2')
        self.assertEqual(hs.random, '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
        self.assertEqual(hs.session_id, '')  # 空Session ID

        # 验证密码套件
        self.assertEqual(hs.ciphers, [
            'TLS_AES_128_GCM_SHA256',
            'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        ])

        # 验证压缩方法
        self.assertEqual(hs.compression, [0])

        # 验证扩展
        exts = hs.extensions
        self.assertEqual(len(exts), 2)

        # 验证SNI扩展
        sni_ext = exts[0]
        self.assertEqual(sni_ext['type'], 'server_name')
        self.assertEqual(sni_ext['sni'], 'example.')

        # 验证Supported Groups扩展
        groups_ext = exts[1]
        self.assertEqual(groups_ext['type'], 'supported_groups')
        self.assertEqual(groups_ext['groups'], [0x001d])



if __name__ == '__main__':
    unittest.main()
