import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QListWidget, QTextEdit, QApplication
)
from PyQt5.QtGui import QFont

class SnifferUI(QMainWindow):
    def __init__(self):
        super().__init__()
        # 初始化布局引用
        self.ctrl_layout = None  # 新增类属性声明
        self._setup_ui()
        self._setup_styles()

    def _setup_ui(self):
        # 主布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # 顶部控制栏（关键修改：将 ctrl_layout 保存为实例变量）
        self.ctrl_layout = QHBoxLayout()  # 改为 self.ctrl_layout
        self.start_btn = QPushButton("▶ 开始捕获")
        self.stop_btn = QPushButton("⏹ 停止")
        self.clear_btn = QPushButton("🗑 清空")
        self.ctrl_layout.addWidget(self.start_btn)
        self.ctrl_layout.addWidget(self.stop_btn)
        self.ctrl_layout.addWidget(self.clear_btn)

        # 新增接口显示标签（正确引用）
        self.iface_label = QLabel("当前接口: 未选择")
        self.ctrl_layout.addWidget(self.iface_label)  # 使用 self.ctrl_layout

        # 数据包列表
        self.packet_list = QListWidget()
        self.packet_list.setFont(QFont("Consolas", 10))

        # 详细信息面板
        self.detail_view = QTextEdit()
        self.detail_view.setReadOnly(True)

        # 布局组合
        layout.addLayout(self.ctrl_layout)
        layout.addWidget(QLabel("捕获的数据包:"))
        layout.addWidget(self.packet_list, 3)  # 3份高度
        layout.addWidget(QLabel("数据包详情:"))
        layout.addWidget(self.detail_view, 2)

    def _setup_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background: #F5F5F5;
            }
            QPushButton {
                background: #4CAF50;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background: #45a049;
            }
            QListWidget, QTextEdit {
                background: white;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: 'Segoe UI';
            }
        """)

    def update_status(self, message):
        """更新状态栏"""
        self.status_bar.showMessage(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SnifferUI()
    window.show()
    sys.exit(app.exec_())