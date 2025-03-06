from scapy.arch.windows import get_windows_if_list as scapy_win_if
from ctypes import windll, Structure, c_uint

# Windows网络类型常量定义
IF_TYPE_ETHERNET = 6
IF_TYPE_IEEE80211 = 71


class MIB_IF_ROW2(Structure):
    _fields_ = [("InterfaceLuid", c_uint * 2),
                ("InterfaceIndex", c_uint)]


def _check_admin():
    """Windows管理员权限验证"""
    try:
        return windll.shell32.IsUserAnAdmin() != 0
    except:
        print("Windows管理员权限验证")
        return False


class NetworkInterfaceDetector:
    def __init__(self):
        if not _check_admin():
            raise PermissionError("请以管理员身份运行程序")

        self.ifaces = self._get_enhanced_interfaces()
        self.selected_iface = None

    def _get_enhanced_interfaces(self):
        """获取增强的接口信息列表"""
        interfaces = []
        try:
            # 使用Scapy接口信息作为基础
            for iface in scapy_win_if():
                # 过滤虚拟接口
                if "virtual" in iface['description'].lower():
                    continue

                # 获取详细类型
                if_type = self._get_interface_type(iface['name'])
                status = self._check_interface_status(iface['name'])

                interfaces.append({
                    'name': iface['name'],
                    'description': iface['description'],
                    'type': if_type,
                    'status': status,
                    'guid': iface['guid']
                })
            return interfaces
        except Exception as e:
            print(f"接口获取失败: {str(e)}")
            return []
        except:
            print("接口获取失败")

    def _get_interface_type(self, iface_name):
        """精确的接口类型检测[6](@ref)"""
        try:
            # 使用Windows原生API检测
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if iface['name'] == iface_name:
                    if iface.get('type') == IF_TYPE_IEEE80211:
                        return "Wi-Fi"
                    elif iface.get('type') == IF_TYPE_ETHERNET:
                        return "以太网"
            return "未知"
        except:
            print("精确的接口类型检测")
            # 备用名称匹配策略
            if any(kw in iface_name.lower() for kw in ['wireless', 'wifi']):
                return "Wi-Fi"
            return "以太网"

    def _check_interface_status(self, iface_name):
        """增强的连接状态检测[4](@ref)"""
        try:
            # 使用更精确的Windows API
            for iface in scapy_win_if():
                if iface['name'] == iface_name:
                    return "已连接" if iface['ips'] else "未连接"
            return "未知"
        except Exception as e:
            print(f"状态检测失败: {str(e)}")
            return "未知"

    def show_interface_menu(self):
        """控制台接口选择菜单"""
        print("\n=== Windows网络接口列表 ===")
        print("ID | 接口名称                | 类型       | 状态      | 描述")
        print("-" * 70)
        for idx, iface in enumerate(self.ifaces, 1):
            print(f"{idx:2} | {iface['name'][:20]:20} | {iface['type']:8} | "
                  f"{iface['status']:8} | {iface['description'][:15]}...")

    def select_interface(self, choice):
        """处理用户选择"""
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(self.ifaces):
                self.selected_iface = self.ifaces[idx]
                return True
            return False
        except:
            print('精确的接口类型检测')
            return False
