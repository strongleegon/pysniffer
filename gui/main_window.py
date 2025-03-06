import numpy as np
import pyqtgraph as pg
from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget, QListWidget, QLabel, QTextEdit, QHBoxLayout, \
    QLineEdit, QPushButton
from PyQt5 import QtWidgets


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
            from core.interface import NetworkInterfaceDetector
            self.detector = NetworkInterfaceDetector()
            self.interfaces = self.detector._get_enhanced_interfaces()
            self.refresh_interface_list()
        except PermissionError as e:
            print("初始化接口检测器", e)
            self.interface_layout.addWidget(QLabel("Error: Please run as administrator!"))
        except:
            print("初始化接口检测器")

        # 数据包捕获选项卡
        self.capture_layout = QVBoxLayout()
        self.packet_table = QTextEdit()
        from PyQt5.QtGui import QFont
        self.packet_table.setFont(QFont("Courier New", 9))
        self.capture_layout.addWidget(self.packet_table)

        self.statistics_table = QTextEdit()
        self.statistics_table.setFont(QFont("Courier New", 9))
        self.capture_layout.addWidget(self.statistics_table)


        self.capture_control_layout = QHBoxLayout()
        # BPF输入框
        self.bpf_input = QLineEdit()
        self.bpf_input.setPlaceholderText("输入BPF过滤规则，例如: tcp port 80")
        self.capture_control_layout.addWidget(QLabel("BPF Filter:"))
        self.capture_control_layout.addWidget(self.bpf_input)

        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.start_capture)
        self.capture_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        self.capture_layout.addWidget(self.stop_button)

        self.capture_tab.setLayout(self.capture_layout)
        # 将控制栏添加到布局
        self.capture_layout.addLayout(self.capture_control_layout)
        self.capture_layout.addWidget(self.packet_table)
        self.capture_layout.addWidget(self.statistics_table)

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
        from core.database import DatabaseManager
        self.db_manager = DatabaseManager()

        # 创建统计信息容器
        self.stats_container = QtWidgets.QWidget()
        self.stats_layout = QtWidgets.QHBoxLayout()
        self.stats_container.setLayout(self.stats_layout)

        # 左侧统计文本
        self.statistics_table = QTextEdit()
        self.statistics_table.setFixedWidth(400)  # 固定宽度
        #捕获控制布局部分
        self.chart_selector = QtWidgets.QComboBox()
        self.chart_selector.addItems(["网络层", "传输层", "应用层"])
        self.capture_control_layout.addWidget(QLabel("显示图表:"))
        self.capture_control_layout.addWidget(self.chart_selector)
        # 创建三个饼图并共享同一显示区域
        self.chart_widget = pg.GraphicsLayoutWidget()
        self.chart_widget.setBackground('w')

        # 创建三个饼图但默认隐藏两个
        self.network_plot = self.create_pie_chart("网络层协议分布")
        self.transport_plot = self.create_pie_chart("传输层协议分布")
        self.application_plot = self.create_pie_chart("应用层协议分布")

        # 初始只显示网络层
        self.transport_plot.hide()
        self.application_plot.hide()
        self.chart_widget.addItem(self.network_plot)

        # 将图表添加到布局
        self.chart_widget.addItem(self.network_plot)
        self.chart_widget.addItem(self.transport_plot)
        self.chart_widget.addItem(self.application_plot)

        # 将组件添加到容器
        self.stats_layout.addWidget(self.statistics_table)
        self.stats_layout.addWidget(self.chart_widget)

        # 将统计容器添加到主布局
        self.capture_layout.addWidget(self.stats_container)

    def create_pie_chart(self, title):
        """创建单个饼图的基础配置"""
        plot = pg.PlotItem()
        plot.setTitle(title, color='k', size='12pt')
        plot.hideAxis('left')
        plot.hideAxis('bottom')
        plot.setAspectLocked()
        return plot

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
            # 获取BPF输入
            bpf_text = self.bpf_input.text().strip()

            # 验证BPF语法
            try:
                from scapy.arch.common import compile_filter
                compile_filter(bpf_text, iface=self.selected_iface['name'])
            except Exception as e:
                self.statusBar().showMessage(f"无效的BPF语法: {str(e)}", 5000)
                return
            except:
                print("无效的bpf语法")

            # 创建嗅探工作线程
            from main import PacketSnifferWorker
            self.sniffer_worker = PacketSnifferWorker(
                self.selected_iface,
                bpf_filter=bpf_text  # 确保传递过滤器参数
            )

            # 初始化线程
            from PyQt5.QtCore import QThread
            self.sniffer_thread = QThread()
            self.sniffer_worker.moveToThread(self.sniffer_thread)

            # 连接信号与槽
            self.sniffer_worker.packet_received.connect(self.display_packet)
            self.sniffer_worker.statistics_updated.connect(self.display_statistics)
            self.sniffer_thread.started.connect(self.sniffer_worker.start_sniffing)
            self.sniffer_worker.finished.connect(self.sniffer_thread.quit)

            # 启动线程
            self.sniffer_thread.start()

            # 更新界面状态
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.statusBar().showMessage(f"已应用BPF过滤器: {bpf_text}", 3000)

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
        from PyQt5.QtGui import QFont
        self.statistics_table.setFont(QFont("Courier New", 9))
        self.statistics_table.append("-- 链路层 --")
        for proto in [ 'Ethernet']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")
        self.statistics_table.append("-- 网络层 --")
        for proto in ['IPv4', 'IPv6', 'ARP','ICMP']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

        self.statistics_table.append("-- 传输层 --")
        for proto in ['TCP', 'UDP' ]:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

        self.statistics_table.append("-- 应用层 --")
        for proto in ['HTTP', 'DNS', 'HTTPS','Other']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

            # 获取当前选择的图表类型
        chart_type = self.chart_selector.currentText()

        # 隐藏所有图表
        self.network_plot.hide()
        self.transport_plot.hide()
        self.application_plot.hide()

        if chart_type == "网络层":
            self.network_plot.show()
            self.update_pie_chart(
                self.network_plot,
                labels=['IPv4', 'IPv6', 'ARP', 'ICMP', 'Other'],
                values=[
                    stats.get('IPv4', 0),
                    stats.get('IPv6', 0),
                    stats.get('ARP', 0),
                    stats.get('ICMP',0),
                ],
                colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4','#6A5ACD']
        )
        elif chart_type == "传输层":
            self.transport_plot.show()
            self.update_pie_chart(
                self.transport_plot,
                labels=['TCP', 'UDP', 'TransportOther'],
                values=[
                    stats.get('TCP', 0),
                    stats.get('UDP', 0),
                    stats.get('TransportOther', 0)  # 修正键名
                ],
                colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']  # 3个颜色对应3个标签
        )

        # 应用层饼图（确保统计收集）
        elif chart_type == "应用层":
            self.application_plot.show()
            self.update_pie_chart(
                self.application_plot,
                labels=['HTTP', 'DNS', 'HTTPS', 'ApplicationOther'],
                values=[
                    stats.get('HTTP', 0),
                    stats.get('DNS', 0),
                    stats.get('HTTPS', 0),
                    stats.get('ApplicationOther', 0)
                    ],
                colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#6A5ACD']  # 4个颜色对应4个标签
        )
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

    def update_pie_chart(self, plot, labels, values, colors):
        """更新单个饼图"""
        plot.clear()

        # 过滤零值
        valid_data = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]
        if not valid_data:
            return

        labels, values, colors = zip(*valid_data)
        total = sum(values)
        if total == 0:
            return

        # 计算角度
        angles = np.cumsum(np.array(values) / total * 360)
        start_angle = 0

        # 绘制扇形
        for i, (label, value, color) in enumerate(zip(labels, values, colors)):
            if value == 0:
                continue

            end_angle = start_angle + (value / total * 360)

            # 创建扇形图形项
            wedge = pg.QtWidgets.QGraphicsPathItem()
            path = pg.QtGui.QPainterPath()

            # 计算扇形路径
            radius = 0.8
            path.moveTo(0, 0)
            path.arcTo(-radius, -radius, radius * 2, radius * 2, start_angle, end_angle - start_angle)
            path.lineTo(0, 0)

            wedge.setPath(path)
            wedge.setBrush(pg.mkBrush(color))
            wedge.setPen(pg.mkPen('k', width=1))

            # 添加文字标签
            if value / total > 0.1:  # 只显示大于10%的标签
                mid_angle = np.deg2rad(start_angle + (end_angle - start_angle) / 2)
                text_x = 0.6 * np.cos(mid_angle)
                text_y = 0.6 * np.sin(mid_angle)

                text = pg.TextItem(f"{label}\n{value / total:.1%}", color='k', anchor=(0.5, 0.5))
                text.setPos(text_x, text_y)
                plot.addItem(text)

            plot.addItem(wedge)
            start_angle = end_angle

        # 添加图例
        legend = pg.LegendItem(offset=(50, 50))
        for label, color in zip(labels, colors):
            legend.addItem((pg.PlotDataItem(pen=color), label))
        legend.setParentItem(plot)