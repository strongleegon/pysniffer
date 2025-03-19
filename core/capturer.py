import queue
import sys
import threading

from scapy.all import sniff
from scapy.arch.common import compile_filter  # 验证BPF的核心函数
from scapy.error import Scapy_Exception
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

from core.interface import NetworkInterfaceDetector


class PacketSniffer:
    def __init__(self, interface,bpf_filter=None):
        self.interface = interface['name']
        self.bpf_filter =bpf_filter
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.lock = threading.Lock()  # 新增线程锁

    def _packet_handler(self, pkt):
        """数据包处理回调（线程安全）"""
        with self.lock:
            self.packet_queue.put(pkt)

    def set_bpf_filter(self, new_filter):
        """设置并验证BPF过滤器"""
        try:
            # 验证BPF语法有效性
            compile_filter(filter_exp=new_filter, iface=self.interface)
            self.bpf_filter = new_filter
            print(f"BPF过滤器已更新: {new_filter}")
        except Scapy_Exception as e:
            print(f"无效的BPF语法: {e}")
        except:
            print("bpf语法")

    def start_sniffing(self):
        """启动抓包线程"""
        self.is_sniffing = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop)
        self.sniffer_thread.start()

    def _sniff_loop(self):
        """抓包主循环（启用混杂模式）"""
        sniff(
            iface=self.interface,
            filter=self.bpf_filter or "",
            prn=self._packet_handler,
            store=False,
            promisc=True,  # 显式启用混杂模式
            stop_filter=lambda _: not self.is_sniffing
        )

    def stop_sniffing(self):
        """停止抓包"""
        self.is_sniffing = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)


if __name__ == "__main__":
    try:
        # 初始化检测器
        detector = NetworkInterfaceDetector()
        detector.show_interface_menu()

        # 用户选择
        while True:
            choice = input("\n请输入接口ID (Q退出): ").strip().lower()
            if choice == 'q':
                sys.exit()

            if detector.select_interface(choice):
                target_iface = detector.selected_iface
                print(f"\n已选择接口: {target_iface['name']}")
                print(f"类型: {target_iface['type']}")
                print(f"状态: {target_iface['status']}")
                print(f"描述: {target_iface['description']}")

                # 启动抓包
                sniffer = PacketSniffer(target_iface,bpf_filter="tcp port 80")
                sniffer.start_sniffing()
                input("\n正在捕获流量，按回车停止...")
                sniffer.stop_sniffing()

                # 显示结果
                print("\n捕获到的数据包:")
                while not sniffer.packet_queue.empty():
                    print(sniffer.packet_queue.get())
                break
            else:
                print("无效输入，请重试")

    except PermissionError as e:
        print(f"权限错误: {str(e)}")
    except Exception as e:
        print(f"运行时错误: {str(e)}")
    except:
        print("权限错误或运行时错误")