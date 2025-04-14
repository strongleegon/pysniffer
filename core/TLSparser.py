import struct
from collections import namedtuple

# 定义TLS结构体
TLSRecord = namedtuple('TLSRecord', ['type', 'version', 'length', 'handshake'])
Handshake = namedtuple('Handshake',
                       ['type', 'length', 'version', 'random', 'session_id', 'ciphers', 'compression', 'extensions'])


class TLSParser:
    def __init__(self):
        # 最新IANA密码套件映射 (2023年更新)
        self.cipher_suites = {
            0x1301: 'TLS_AES_128_GCM_SHA256',
            0x1302: 'TLS_AES_256_GCM_SHA384',
            0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
            0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0x009E: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
            0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
            0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
            0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
        }

        # TLS扩展类型映射
        self.extensions = {
            0x0000: 'server_name',
            0x0005: 'status_request',
            0x000a: 'supported_groups',
            0x000d: 'signature_algorithms',
            0x000f: 'heartbeat',
            0x0010: 'application_layer_protocol_negotiation',
            0x0017: 'extended_master_secret',
            0x002b: 'supported_versions',
            0x002d: 'psk_key_exchange_modes',
            0x0033: 'key_share'
        }

    def parse_record(self, data):
        """解析TLS记录层"""
        if len(data) < 5:
            return None

        type_, version, length = struct.unpack('>BHH', data[:5])
        return TLSRecord(
            type=type_,
            version=f'TLS 1.{version - 0x0301}' if version >= 0x0301 else f'SSL {version}',
            length=length,
            handshake=self.parse_handshake(data[5:5 + length]))

    def parse_handshake(self, data):
        """解析握手协议"""
        if len(data) < 4:
            return None

        # 解析类型和长度（1字节类型 + 3字节长度）
        hs_type = data[0]
        hs_len_bytes = data[1:4]
        hs_len = (hs_len_bytes[0] << 16) | (hs_len_bytes[1] << 8) | hs_len_bytes[2]

        # 检查数据长度是否足够
        if len(data) < 4 + hs_len:
            return None  # 数据不足，无法解析

        # 版本位于第4-6字节
        version = struct.unpack('>H', data[4:6])[0]

        # Random（32字节）
        random = data[6:38]

        # Session ID
        session_id_len = data[38]
        session_id = data[39:39 + session_id_len]

        # 密码套件
        ptr = 39 + session_id_len
        cipher_len = struct.unpack('>H', data[ptr:ptr + 2])[0]
        ptr += 2
        ciphers = self._parse_cipher_suites(data[ptr:ptr + cipher_len])
        ptr += cipher_len

        # 压缩方法
        comp_len = data[ptr]
        ptr += 1
        compression = self._parse_compression_methods(data[ptr:ptr + comp_len])
        ptr += comp_len

        # 扩展
        extensions = []
        if ptr + 2 <= len(data):
            ext_len = struct.unpack('>H', data[ptr:ptr + 2])[0]
            ptr += 2
            extensions = self._parse_extensions(data[ptr:ptr + ext_len])

        return Handshake(
            type=hs_type,
            length=hs_len,
            version=f'TLS 1.{version - 0x0301}' if version >= 0x0301 else f'SSL {version}',
            random=random.hex(),
            session_id=session_id.hex(),
            ciphers=ciphers,
            compression=compression,
            extensions=extensions
        )

    def _parse_cipher_suites(self, data):
        """解析密码套件列表"""
        ciphers = []
        for i in range(0, len(data), 2):
            code = struct.unpack('>H', data[i:i + 2])[0]
            ciphers.append(self.cipher_suites.get(code, f'UNKNOWN_0x{code:04X}'))
        return ciphers

    def _parse_compression_methods(self, data):
        """解析压缩方法"""
        return [struct.unpack('B', bytes([b]))[0] for b in data]

    def _parse_extensions(self, data):
        """解析TLS扩展"""
        exts = []
        ptr = 0
        while ptr < len(data):
            ext_type = struct.unpack('>H', data[ptr:ptr + 2])[0]
            ext_len = struct.unpack('>H', data[ptr + 2:ptr + 4])[0]
            ext_data = data[ptr + 4:ptr + 4 + ext_len]

            # 特殊处理关键扩展
            ext_name = self.extensions.get(ext_type, f'UNKNOWN_0x{ext_type:04X}')
            parsed = {
                'type': ext_name,
                'data': ext_data.hex()
            }

            # 解析具体扩展内容
            if ext_type == 0x0000:  # SNI
                parsed['sni'] = self._parse_sni(ext_data)
            elif ext_type == 0x000a:  # Supported Groups
                parsed['groups'] = self._parse_supported_groups(ext_data)
            elif ext_type == 0x0010:  # ALPN
                parsed['protocols'] = self._parse_alpn(ext_data)

            exts.append(parsed)
            ptr += 4 + ext_len
        return exts

    def _parse_sni(self, data):
        """解析服务器名称指示扩展"""
        list_len = struct.unpack('>H', data[:2])[0]
        name_type = data[2]
        name_len = struct.unpack('>H', data[3:5])[0]
        return data[5:5 + name_len].decode('utf-8')

    def _parse_supported_groups(self, data):
        """解析支持的椭圆曲线列表"""
        groups = []
        group_len = struct.unpack('>H', data[:2])[0]
        for i in range(2, 2 + group_len, 2):
            group_id = struct.unpack('>H', data[i:i + 2])[0]
            groups.append(group_id)
        return groups

    def _parse_alpn(self, data):
        """解析ALPN协议列表"""
        protocols = []
        ptr = 0
        while ptr < len(data):
            length = data[ptr]
            protocols.append(data[ptr + 1:ptr + 1 + length].decode('utf-8'))
            ptr += 1 + length
        return protocols



