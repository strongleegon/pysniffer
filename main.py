import sys
import time
import keyboard
from threading import Thread, Event
from core.database import DatabaseManager
from core.parser import EnhancedProtocolParser
from core.capturer import PacketSniffer



def main():
    db_manager = DatabaseManager()
    # 初始化协议解析器
    # 初始化接口检测器
    try:
        from core.interface import NetworkInterfaceDetector
        detector = NetworkInterfaceDetector()
    except PermissionError as e:
        print(f"错误: {str(e)}")
        sys.exit(1)

    # 显示接口菜单
    detector.show_interface_menu()

    # 用户选择接口
    while True:
        choice = input("\n请输入要监听的接口ID (Q退出): ").strip().lower()
        if choice == 'q':
            return
        if detector.select_interface(choice):
            iface = detector.selected_iface
            print(f"\n已选择接口: {iface['name']} ({iface['description']})")
            break
        print("无效的选择，请重新输入")

    # 初始化抓包组件

    sniffer = PacketSniffer(iface)
    parser = EnhancedProtocolParser(db_manager)
    stop_event = Event()

    # 启动异步键盘监听
    def keyboard_listener():
        keyboard.wait('ctrl+q')
        print("\n检测到停止信号...")
        stop_event.set()

    keyboard_thread = Thread(target=keyboard_listener)
    keyboard_thread.daemon = True
    keyboard_thread.start()

    # 启动抓包
    print("\n开始捕获流量... (Ctrl+Q 停止)")
    sniffer.start_sniffing()

    try:
        last_stat_time = time.time()
        stat_interval = 2  # 统计信息刷新间隔

        while not stop_event.is_set():
            # 处理数据包队列
            processed = 0
            while not sniffer.packet_queue.empty() and processed < 100:
                pkt = sniffer.packet_queue.get()
                analysis = parser.parse_packet(pkt)

                # 实时显示数据包
                summary = format_packet_summary(analysis)
                print(f"[{time.strftime('%H:%M:%S')}] {summary}")

                processed += 1
                if stop_event.is_set():
                    break

            # 定期显示统计信息
            if time.time() - last_stat_time > stat_interval:
                display_statistics(parser.protocol_stats)
                last_stat_time = time.time()

            time.sleep(0.1)  # 降低CPU占用

    except Exception as e:
        print(f"\n发生错误: {str(e)}")
    finally:
        # 清理资源
        sniffer.stop_sniffing()
        keyboard.unhook_all()

        # 显示最终报告
        print("\n正在生成最终报告...")
        display_final_report(parser.protocol_stats)


def format_packet_summary(analysis):
    """优化的数据包摘要格式化"""
    meta = analysis.get('metadata', {})
    layers = analysis.get('layers', {})

    # 协议层级检测
    hierarchy = analysis.get('layer_hierarchy', '').split('/')
    proto = hierarchy[-1] if hierarchy else 'Unknown'

    # 地址信息构建
    src = meta.get('src_ip') or meta.get('src_mac', '?')
    dst = meta.get('dst_ip') or meta.get('dst_mac', '?')
    ports = ""

    # 端口信息处理
    if proto in ['TCP', 'UDP']:
        src_port = meta.get('src_port', '')
        dst_port = meta.get('dst_port', '')
        ports = f":{src_port} → :{dst_port}"

    # 协议特定信息
    details = []
    if proto == 'HTTP':
        http = layers.get('HTTP', {})
        if http.get('type') == 'Request':
            details.append(f"{http.get('method', '')} {http.get('path', '')}")
        else:
            details.append(f"Status {http.get('status_code', '')}")
    elif proto == 'DNS':
        dns = layers.get('DNS', {})
        if dns.get('qr') == 'query':
            details.append(f"Q: {len(dns.get('questions', []))}")
        else:
            details.append(f"A: {len(dns.get('answers', []))}")
    elif proto == 'ICMP':
        details.append(f"Type:{meta.get('icmp_type', '?')}")

    return f"{proto} {' '.join(details)} | {src}{ports} → {dst}"


def display_statistics(stats):
    """实时统计显示优化"""
    print("\n=== 实时统计 ===")
    total = sum(stats.values())
    for proto in ['Ethernet', 'IPv4', 'TCP', 'UDP', 'HTTP', 'DNS']:
        count = stats.get(proto, 0)
        print(f"{proto:10}: {count} ({count / total:.1%})" if total > 0 else f"{proto:10}: {count}")
    print("=" * 40)


def display_final_report(stats):
    """增强最终报告"""
    print("\n=== 捕获统计报告 ===")
    total = sum(stats.values())
    print(f"总数据包数: {total}")

    # 主要协议统计
    print("\n[ 主要协议 ]")
    for proto in ['TCP', 'UDP', 'HTTP', 'DNS', 'ICMP']:
        count = stats.get(proto, 0)
        print(f"  {proto:8}: {count} ({count / total:.1%})" if total > 0 else f"  {proto:8}: {count}")

    # 网络层统计
    print("\n[ 网络层 ]")
    for proto in ['IPv4', 'Ethernet']:
        count = stats.get(proto, 0)
        print(f"  {proto:8}: {count} ({count / total:.1%})" if total > 0 else f"  {proto:8}: {count}")

    print("=" * 40)


if __name__ == "__main__":
    main()