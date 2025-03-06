import sys
import time
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QApplication

from core.capturer import PacketSniffer
from core.database import DatabaseManager
from core.parser import EnhancedProtocolParser
from gui.main_window import TrafficAnalyzerGUI
# 添加导入
from warning.pngwarning import WarningFilter


class PacketSnifferWorker(QObject):
    packet_received = pyqtSignal(dict)
    statistics_updated = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, iface, bpf_filter=None):
        super().__init__()
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.sniffer = PacketSniffer(self.iface, self.bpf_filter)
        self.packet_queue = []
        self.is_running = False
        self.db_manager = DatabaseManager()
        import warnings
        warnings.filterwarnings("ignore", category=UserWarning, module="PIL")

        # 初始化警告过滤器（可配置参数）
        self.warning_filter = WarningFilter(
            patterns=["iCCP: known incorrect sRGB profile", "BPF filter"],
            log_file="sniffer_warnings.log",
            suppress_pillow_warnings=True
        )

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


if __name__ == "__main__":
    # 在主程序初始化时应用全局过滤
    with WarningFilter(suppress_pillow_warnings=True,log_file="app_warnings.log"):
        app = QApplication(sys.argv)
        window = TrafficAnalyzerGUI()
        window.show()
        sys.exit(app.exec_())
