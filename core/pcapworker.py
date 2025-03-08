import sqlite3
from PyQt5.QtCore import QThread, pyqtSignal
from scapy.layers.l2 import Ether
from scapy.utils import PcapReader, PcapWriter


class PCAPWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, db_manager, mode, path):
        super().__init__()
        self.db_manager = db_manager
        self.mode = mode  # 'import' 或 'export'
        self.path = path
        self.batch_size = 1000  # 批量处理大小

    def run(self):
        try:
            if self.mode == 'import':
                total = self.get_pcap_count()
                self.import_pcap(total)
                self.finished.emit(True, f"成功导入{total}个数据包")
            else:
                count = self.export_pcap()
                self.finished.emit(True, f"成功导出{count}个数据包")
        except Exception as e:
            self.finished.emit(False, f"操作失败: {str(e)}")

    def get_pcap_count(self):
        """高效获取PCAP文件中的数据包总数"""
        count = 0
        with PcapReader(self.path) as reader:
            for _ in reader:
                count += 1
        return count

    def import_pcap(self, total):
        """分批导入PCAP文件到数据库"""
        conn = sqlite3.connect(self.db_manager.db_name)
        cursor = conn.cursor()

        try:
            with PcapReader(self.path) as reader:
                batch = []
                imported = 0

                for pkt in reader:
                    if pkt is None:
                        break

                    batch.append((bytes(pkt),))
                    if len(batch) >= self.batch_size:
                        cursor.executemany(
                            "INSERT INTO packets (raw_packet) VALUES (?)",
                            batch
                        )
                        conn.commit()
                        imported += len(batch)
                        self.progress.emit(int((imported / total) * 100))
                        batch = []

                # 处理剩余的数据包
                if batch:
                    cursor.executemany(
                        "INSERT INTO packets (raw_packet) VALUES (?)",
                        batch
                    )
                    conn.commit()
                    imported += len(batch)
                    self.progress.emit(100)
        finally:
            conn.close()

    def export_pcap(self):
        """从数据库导出到PCAP文件"""
        conn = sqlite3.connect(self.db_manager.db_name)
        cursor = conn.cursor()

        try:
            # 获取总数据包数
            cursor.execute("SELECT COUNT(*) FROM packets")
            total = cursor.fetchone()[0]
            if total == 0:
                return 0

            # 分批读取数据
            offset = 0
            with PcapWriter(self.path) as writer:
                while offset < total:
                    cursor.execute(
                        "SELECT raw_packet FROM packets LIMIT ? OFFSET ?",
                        (self.batch_size, offset)
                    )
                    batch = cursor.fetchall()

                    for row in batch:
                        writer.write(Ether(row[0]))

                    offset += len(batch)
                    self.progress.emit(int((offset / total) * 100))
            return total
        finally:
            conn.close()
