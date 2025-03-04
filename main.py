import sys
import time

from PyQt5.QtCore import QThread, pyqtSignal, QObject
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton, QListWidget, \
    QTextEdit, QTabWidget

from core.capturer import PacketSniffer
from core.database import DatabaseManager
from core.interface import NetworkInterfaceDetector
from core.parser import EnhancedProtocolParser


class TrafficAnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("sniffingv1.0")
        self.setGeometry(100, 100, 1200, 800)
        self.widget = QWidget()
        self.setCentralWidget(self.widget)
        self.layout = QVBoxLayout()
        self.widget.setLayout(self.layout)

        # 创建标签页
        self.tabs = QTabWidget()
        self.interface_tab = QWidget()
        self.capture_tab = QWidget()
        self.report_tab = QWidget()
        self.tabs.addTab(self.interface_tab, "选择接口")
        self.tabs.addTab(self.capture_tab, "捕获数据包")
        self.tabs.addTab(self.report_tab, "数据包报告")
        self.layout.addWidget(self.tabs)

        # 网络接口选项卡
        self.interface_list = QListWidget()
        self.interface_list.itemClicked.connect(self.select_interface)
        self.interface_layout = QVBoxLayout()
        self.interface_layout.addWidget(QLabel("Available Interfaces:"))
        self.interface_layout.addWidget(self.interface_list)
        self.interface_tab.setLayout(self.interface_layout)

        # 初始化接口检测器
        try:
            self.detector = NetworkInterfaceDetector()
            self.interfaces = self.detector._get_enhanced_interfaces()
            self.refresh_interface_list()
        except PermissionError:
            self.interface_layout.addWidget(QLabel("Error: Please run as administrator!"))

        # 数据包捕获选项卡
        self.capture_layout = QVBoxLayout()
        self.packet_table = QTextEdit()
        self.packet_table.setFont(QFont("Courier New", 9))
        self.capture_layout.addWidget(self.packet_table)

        self.statistics_table = QTextEdit()
        self.statistics_table.setFont(QFont("Courier New", 9))
        self.capture_layout.addWidget(self.statistics_table)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.capture_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        self.capture_layout.addWidget(self.stop_button)

        self.capture_tab.setLayout(self.capture_layout)

        # 捕获报告选项卡
        self.report_text = QTextEdit()
        self.report_text.setFont(QFont("Courier New", 9))
        self.report_layout = QVBoxLayout()
        self.report_layout.addWidget(self.report_text)
        self.report_tab.setLayout(self.report_layout)

        # 核心组件
        self.selected_iface = None
        self.sniffer_thread = None
        self.sniffer_worker = None
        self.db_manager = DatabaseManager()

    def refresh_interface_list(self):
        self.interface_list.clear()
        for idx, iface in enumerate(self.interfaces, 1):
            item_text = f"{idx:2} | {iface['name'][:20]:20} | {iface['type']:8} | " \
                        f"{iface['status']:8} | {iface['description'][:15]}..."
            self.interface_list.addItem(item_text)

    def select_interface(self, item):
        idx = int(item.text().split('|')[0].strip()) - 1
        if 0 <= idx < len(self.interfaces):
            self.selected_iface = self.interfaces[idx]
            print(f"Selected interface: {self.selected_iface}")

    def start_capture(self):
        if self.selected_iface:
            self.sniffer_worker = PacketSnifferWorker(self.selected_iface)
            self.sniffer_thread = QThread()
            self.sniffer_worker.moveToThread(self.sniffer_thread)

            self.sniffer_worker.packet_received.connect(self.display_packet)
            self.sniffer_worker.statistics_updated.connect(self.display_statistics)
            self.sniffer_thread.started.connect(self.sniffer_worker.start_sniffing)
            self.sniffer_worker.finished.connect(self.sniffer_thread.quit)
            self.sniffer_worker.finished.connect(self.sniffer_worker.deleteLater)
            self.sniffer_thread.finished.connect(self.sniffer_thread.deleteLater)

            self.sniffer_thread.start()

            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)

    def stop_capture(self):
        if self.sniffer_thread and self.sniffer_worker:
            self.sniffer_worker.stop_sniffing()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait()

            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

    def display_packet(self, packet_info):
        summary = self.format_packet_summary(packet_info)
        self.packet_table.append(summary)
        self.packet_table.verticalScrollBar().setValue(self.packet_table.verticalScrollBar().maximum())

    def display_statistics(self, stats):
        self.statistics_table.clear()
        self.statistics_table.setFont(QFont("Courier New", 9))
        self.statistics_table.append("-- 网络层 --")
        for proto in ['IPv4', 'IPv6', 'ARP', 'Ethernet']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

        self.statistics_table.append("-- 传输层 --")
        for proto in ['TCP', 'UDP', 'ICMP']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

        self.statistics_table.append("-- 应用层 --")
        for proto in ['HTTP', 'DNS', 'Other']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

    def format_packet_summary(self, packet_info):
        layers = packet_info.get('layer_hierarchy', '').split('/')
        proto = layers[-1] if layers else 'Unknown'
        metadata = packet_info.get('metadata', {})
        src = metadata.get('src_ip', metadata.get('src_mac', ''))
        dst = metadata.get('dst_ip', metadata.get('dst_mac', ''))
        ports = ""
        if 'src_port' in metadata and 'dst_port' in metadata:
            ports = f":{metadata['src_port']} → :{metadata['dst_port']}"
        details = []
        if 'HTTP' in layers:
            http = packet_info.get('layers', {}).get('HTTP', {})
            if http.get('type') == 'Request':
                details.append(f"HTTP {http.get('method', '')} {http.get('path', '')}")
            else:
                details.append(f"HTTP Status {http.get('status_code', '')}")
        elif 'DNS' in layers:
            dns = packet_info.get('layers', {}).get('DNS', {})
            if dns.get('qr') == 'query':
                details.append(f"DNS Query {dns.get('questions', [{}])[0].get('name', '')}")
            else:
                details.append(f"DNS Response {dns.get('answers', [{}])[0].get('name', '')}")
        elif 'ICMP' in layers:
            details.append(f"ICMP Type {metadata.get('icmp_type', '')}")
        return f"{proto} {' '.join(details)} | {src}{ports} → {dst}"


class PacketSnifferWorker(QObject):
    packet_received = pyqtSignal(dict)
    statistics_updated = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.sniffer = PacketSniffer(self.iface)
        self.packet_queue = []
        self.is_running = False
        self.db_manager = DatabaseManager()

    def start_sniffing(self):
        self.is_running = True
        self.sniffer.start_sniffing()
        parser = EnhancedProtocolParser()
        while self.is_running:
            if self.sniffer.packet_queue.qsize() > 0:
                pkt = self.sniffer.packet_queue.get()
                analysis = parser.parse_packet(pkt)
                self.packet_received.emit(analysis)
                self.statistics_updated.emit(parser.protocol_stats)
                self.db_manager.save_packet(analysis)
            else:
                time.sleep(0.01)

    def stop_sniffing(self):
        self.is_running = False
        self.sniffer.stop_sniffing()
        self.finished.emit()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TrafficAnalyzerGUI()
    window.show()
    sys.exit(app.exec_())
