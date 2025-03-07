import time
import traceback

import numpy as np
import pyqtgraph as pg
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget, QListWidget, QLabel, QTextEdit, QHBoxLayout, \
    QLineEdit, QPushButton, QFileDialog


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
        # 报告选项卡增强
        self.report_layout = QVBoxLayout()

        # 添加控制按钮栏
        self.report_control = QHBoxLayout()
        self.generate_report_btn = QPushButton("生成流量报告")
        self.export_report_btn = QPushButton("导出报告")
        self.clear_report_btn = QPushButton("清空报告")

        # 设置按钮样式
        for btn in [self.generate_report_btn, self.export_report_btn, self.clear_report_btn]:
            btn.setFixedHeight(30)
            btn.setStyleSheet("QPushButton {background: #f0f0f0; border: 1px solid #999;}")

        self.report_control.addWidget(self.generate_report_btn)
        self.report_control.addWidget(self.export_report_btn)
        self.report_control.addWidget(self.clear_report_btn)
        self.report_control.addStretch()

        # 报告显示区域增强
        self.report_text = QTextEdit()
        self.report_text.setStyleSheet("""
                   QTextEdit {
                       background: #f8f8f8;
                       border: 1px solid #ccc;
                       font-family: Consolas;
                       font-size: 11pt;
                   }
               """)

        # 布局组装
        self.report_layout.addLayout(self.report_control)
        self.report_layout.addWidget(self.report_text)
        self.report_tab.setLayout(self.report_layout)

        # 信号连接
        self.generate_report_btn.clicked.connect(self.generate_flow_report)

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

        #添加图例
        self._init_legends()

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
        self.capturing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.generate_report_btn.setEnabled(False)  # 新增
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
        self.capturing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.generate_report_btn.setEnabled(True)  # 新增
        if self.sniffer_thread and self.sniffer_worker:
            self.sniffer_worker.stop_sniffing()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait()

            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.generate_report_btn.setEnabled(True)
            self.export_report_btn.setEnabled(True)

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
        for proto in ['HTTP', 'DNS', 'HTTPS',
            'SIP',  'FTP', 'SMTP',
            'POP3', 'IMAP']:
            self.statistics_table.append(f"{proto:10}: {stats.get(proto, 0)}")

            # 获取当前选择的图表类型
        chart_type = self.chart_selector.currentText()
        for legend in self.legends.values():
            legend.hide()
            # 根据当前选择显示对应图例
        if chart_type == "网络层":
            self.legends['network'].show()
        elif chart_type == "传输层":
            self.legends['transport'].show()
        elif chart_type == "应用层":
            self.legends['application'].show()

        # 隐藏所有图表
        self.network_plot.hide()
        self.transport_plot.hide()
        self.application_plot.hide()

        if chart_type == "网络层":
            self.network_plot.show()
            self.update_pie_chart(
                self.network_plot,
                labels=['IPv4', 'IPv6', 'ARP', 'ICMP'],
                values=[
                    stats.get('IPv4', 0),
                    stats.get('IPv6', 0),
                    stats.get('ARP', 0),
                    stats.get('ICMP',0),
                ],
                colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
        )
        elif chart_type == "传输层":
            self.transport_plot.show()
            self.update_pie_chart(
                self.transport_plot,
                labels=['TCP', 'UDP', ],
                values=[
                    stats.get('TCP', 0),
                    stats.get('UDP', 0),
                ],
                colors=['#FF6B6B', '#4ECDC4']  # 2个颜色对应2个标签
        )

        # 应用层饼图（确保统计收集）
        elif chart_type == "应用层":
            self.application_plot.show()
            self.update_pie_chart(
                self.application_plot,
                labels=['HTTP', 'DNS', 'HTTPS',
            'SIP',  'FTP', 'SMTP',
            'POP3', 'IMAP'],
                values=[
                    stats.get('HTTP', 0),
                    stats.get('DNS', 0),
                    stats.get('HTTPS', 0),
                    stats.get('SIP',0),
                    stats.get('FTP', 0),
                    stats.get('SMTP', 0),
                    stats.get('POP3', 0),
                    stats.get('IMAP', 0),
                    ],
                colors=['#4B8BBE', '#F7B267', '#7FB069', '#D64550', '#6C5B7B', '#5C9EAD', '#F4D35E', '#E56399']  # 8个颜色对应8个标签
        )

    def format_packet_summary(self, packet_info):
        layers = packet_info.get('layer_hierarchy', '').split('/')
        metadata = packet_info.get('metadata', {})

        # 协议显示优化（显示所有应用层协议）
        app_protocols = [layer for layer in layers if layer in {
            'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH', 'SIP'
        }]
        proto_display = " → ".join(app_protocols) if app_protocols else 'Unknown'

        # 地址信息格式化
        src = metadata.get('src_ip') or metadata.get('src_mac', 'Unknown')
        dst = metadata.get('dst_ip') or metadata.get('dst_mac', 'Unknown')

        # 端口信息格式化
        port_info = ""
        if 'src_port' in metadata and 'dst_port' in metadata:
            port_info = f":{metadata['src_port']} → :{metadata['dst_port']}"

        # 协议详细信息提取
        details = []
        layers_data = packet_info.get('layers', {})

        # TLS 信息
        if 'TLS' in layers:
            tls_data = layers_data.get('TLS', {})
            details.append(
                f"TLS {tls_data.get('version', '')} "
                f"SNI: {tls_data.get('server_name', '')}"
            )

        # HTTP 信息
        if 'HTTP' in layers_data:
            http_data = layers_data['HTTP']
            if http_data.get('type') == 'Request':
                detail = f"{http_data.get('method', '')} {http_data.get('path', '')}"
            else:
                detail = f"Status {http_data.get('status_code', '')}"
            details.append(f"HTTP {detail}")

        if 'DNS' in layers_data:
            dns_data = layers_data['DNS']

            def _dns_data_to_str(data):
                """转换 DNS 数据为可读字符串"""
                if isinstance(data, bytes):
                    try:
                        return data.decode('utf-8', errors='replace')
                    except UnicodeDecodeError:
                        return '.'.join(str(b) for b in data)  # 处理二进制标签格式
                return str(data)

            # 处理查询
            if dns_data.get('qr') == 'query':
                queries = []
                for q in dns_data.get('questions', []):
                    name = _dns_data_to_str(q.get('name', ''))
                    queries.append(name)
                details.append(f"DNS Query: {', '.join(queries)}")

            # 处理响应
            else:
                answers = []
                for ans in dns_data.get('answers', []):
                    data = _dns_data_to_str(ans.get('data', ''))
                    # 处理 IP 地址类型（A/AAAA 记录）
                    if ans.get('type') in ('A', 'AAAA'):
                        try:
                            from socket import inet_ntop, AF_INET, AF_INET6
                            if ans['type'] == 'A' and len(data) == 4:
                                data = inet_ntop(AF_INET, data)
                            elif ans['type'] == 'AAAA' and len(data) == 16:
                                data = inet_ntop(AF_INET6, data)
                        except (ValueError, OSError, ImportError):
                            pass
                    answers.append(data)
                details.append(f"DNS Response: {', '.join(answers)}")

        # ICMP 信息
        if 'ICMP' in layers:
            details.append(
                f"ICMP Type {metadata.get('icmp_type', '?')}/"
                f"Code {metadata.get('icmp_code', '?')}"
            )

        # 最终格式化
        return (
            f"[{proto_display}] {', '.join(details)} | "
            f"{src}{port_info} → {dst}"
        )

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
        # 创建临时列表保存图形项
        graphics_items = []

        # 计算角度
        angles = np.cumsum(np.array(values) / total * 360)
        start_angle = 0

        # 绘制扇形

        for i, (label, value, color) in enumerate(zip(labels, values, colors)):
            end_angle = start_angle + (value / total * 360)

        # 创建文字标签（先）
            if value / total > 0.05:  # 显示5%以上的标签
                mid_angle = np.deg2rad(start_angle + (end_angle - start_angle) / 2)
                text_x = 1.2 * np.cos(mid_angle)  # 增大半径
                text_y = 1.2 * np.sin(mid_angle)

                text = pg.TextItem(
                    f"{label}\n{value / total:.1%}",
                    color='k',
                    anchor=(0.5, 0.5),
                    border='w',
                    fill=(255, 255, 255, 128)
                )
                text.setPos(text_x, text_y)
                text.setZValue(100)  # 高层级
                graphics_items.append(text)

        # 创建扇形（后）
            wedge = pg.QtWidgets.QGraphicsPathItem()
            radius = 0.8
            path = pg.QtGui.QPainterPath()
            path.moveTo(0, 0)
            path.arcTo(-radius, -radius, radius * 2, radius * 2, start_angle, end_angle - start_angle)
            path.lineTo(0, 0)
            wedge.setPath(path)
            wedge.setBrush(pg.mkBrush(color))
            wedge.setPen(pg.mkPen('k', width=1))
            wedge.setZValue(10)  # 低层级
            graphics_items.append(wedge)

            start_angle = end_angle

        # 批量添加图形项（保持添加顺序）
        for item in graphics_items:
            plot.addItem(item)

    def _init_legends(self):
        """预创建所有图例并设置初始隐藏"""
        # 定义各层图例参数
        legend_config = {
            'network': {
                'labels': ['IPv4', 'IPv6', 'ARP', 'ICMP'],
                'colors': ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'],  # 5色
                'position': (70, 70)
            },
            'transport': {
                'labels': ['TCP', 'UDP'],
                'colors': ['#FF6B6B', '#4ECDC4'],  # 3色
                'position': (70, 120)
            },
            'application': {
                'labels': ['HTTP', 'DNS', 'HTTPS',
            'SIP',  'FTP', 'SMTP',
            'POP3', 'IMAP'],
                'colors': ['#4B8BBE', '#F7B267', '#7FB069', '#D64550', '#6C5B7B', '#5C9EAD', '#F4D35E', '#E56399'],  # 4色
                'position': (70, 170)
            }
        }
        for layer, config in legend_config.items():
            if len(config['labels']) != len(config['colors']):
                raise ValueError(
                    f"{layer} 层的标签数量({len(config['labels'])}) "
                    f"与颜色数量({len(config['colors'])})不匹配！"
                )

        # 创建图例存储字典
        self.legends = {}

        for layer, config in legend_config.items():
            legend = pg.LegendItem(offset=config['position'], verSpacing=-5)
            legend.setZValue(200)

            # 转换颜色字符串为QColor对象
            colors = [pg.mkColor(color_str) for color_str in config['colors']]

            # 创建占位图形项（修正版）
            for label, color in zip(config['labels'], colors):
                # 创建彩色矩形块
                bar_item = pg.BarGraphItem(
                    x=[0],
                    height=[1],
                    width=0.8,
                    pen=pg.mkPen(None),  # 无边框
                    brush=pg.mkBrush(color)  # 使用QColor对象
                )

                # 创建关联的曲线项
                curve = pg.PlotDataItem(pen=color)
                curve.setData([], [])  # 空数据

                # 将矩形块和曲线组合使用
                legend.addItem(bar_item, label)

                # 设置文本样式（修正颜色访问方式）
                text_item = legend.items[-1][1]
                text_item.setText(label, color='#333333')
                # 转换为正确的RGBA元组
                rgba = (color.red(), color.green(), color.blue(), 100)
                text_item.fill = pg.mkBrush(*rgba)

            # 将图例添加到图表并隐藏
            self.chart_widget.addItem(legend)
            legend.hide()
            self.legends[layer] = legend

    def generate_flow_report(self):
        """生成流量分析报告并显示"""
        try:
            from core.report import ReportGenerator
            # 检查数据库连接
            if not hasattr(self, 'db_manager') or not self.db_manager:
                raise RuntimeError("数据库未正确初始化")

            # 创建报告生成器
            reporter = ReportGenerator(self.db_manager)

            # 执行报告生成
            start_time = time.time()
            self.statusBar().showMessage("正在生成报告...")
            QtWidgets.QApplication.processEvents()  # 强制刷新界面

            report_content = reporter.generate_flow_report()

            # 显示生成结果
            self.report_text.clear()
            self.report_text.setPlainText(report_content)

            # 显示生成耗时
            elapsed = time.time() - start_time
            self.statusBar().showMessage(f"报告生成完成，耗时{elapsed:.2f}秒", 5000)

        except Exception as e:
            error_msg = f"报告生成失败: {str(e)}"
            self.report_text.setPlainText(error_msg)
            self.statusBar().showMessage(error_msg, 5000)
            print(f"报告生成错误: {traceback.format_exc()}")

    def export_report(self):
        """导出报告到文件"""
        options = QFileDialog.Options()
        path, _ = QFileDialog.getSaveFileName(
            self, "保存报告", "",
            "文本文件 (*.txt);;Markdown文件 (*.md)",
            options=options
        )

        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(self.report_text.toPlainText())
                self.statusBar().showMessage(f"报告已保存至：{path}", 5000)
            except Exception as e:
                self.statusBar().showMessage(f"保存失败：{str(e)}", 5000)

    def clear_report(self):
        """清空报告内容"""
        self.report_text.clear()
        self.statusBar().showMessage("报告内容已清空", 3000)