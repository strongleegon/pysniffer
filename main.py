import sys
import time
from collections import defaultdict
from queue import Queue
from threading import Thread

from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication

from core.capturer import PacketSniffer
from core.database import DatabaseManager
from core.parser import EnhancedProtocolParser
from gui.main_window import TrafficAnalyzerGUI
from warning.pngwarning import WarningFilter


class PacketSnifferWorker(QObject):
    packet_received = pyqtSignal(dict)
    statistics_updated = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, iface, bpf_filter=None):
        super().__init__()
        self.batch_size = 50  # 批量提交数量
        self.packet_batch = []
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.sniffer = PacketSniffer(self.iface, self.bpf_filter)
        self.packet_queue = []
        self.is_running = False
        self.db_manager = DatabaseManager()
        self.protocol_counter = defaultdict(int)
        self.packet_queue = Queue(maxsize=1000)
        self.processing_thread = Thread(target=self._process_queue)
        self.processing_thread.start()
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="PIL")

        # 初始化警告过滤器（可配置参数）
        self.warning_filter = WarningFilter(
            patterns=["iCCP: known incorrect sRGB profile", "BPF filter"],
            log_file="sniffer_warnings.log",
            suppress_pillow_warnings=True
        )

    def process_packet(self, packet):
        """仅做入队操作"""
        self.packet_queue.put(packet)

    def _process_queue(self):
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=0.1)
                # 解析协议层级时更新计数器
                for proto in parsed_packet['layer_hierarchy']:
                    self.protocol_counter[proto] += 1

                # 每10个包发送一次统计更新
                if len(self.packet_buffer) % 10 == 0:
                    self.statistics_updated.emit(dict(self.protocol_counter))
                self.packet_batch.append(processed_data)

                if len(self.packet_batch) >= self.batch_size:
                    self.db_manager.bulk_insert(self.packet_batch)
                    self.packet_batch = []
            except Empty:
                continue

    def start_sniffing(self):
        self.is_running = True
        self.sniffer.start_sniffing()
        parser = EnhancedProtocolParser()

        # 在捕获循环中使用警告过滤器
        with self.warning_filter:
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
        if self.packet_batch:  # 提交剩余数据
            self.db_manager.bulk_insert(self.packet_batch)


if __name__ == "__main__":
    # 在主程序初始化时应用全局过滤
    with WarningFilter(suppress_pillow_warnings=True,log_file="app_warnings.log"):
        app = QApplication(sys.argv)
        window = TrafficAnalyzerGUI()
        # 设置窗口图标
        window.setWindowIcon(QIcon("logo.png"))  # 使用图标文件路径

        # 设置应用图标
        app.setWindowIcon(QIcon("logo.png"))

        window.show()
        sys.exit(app.exec_())
