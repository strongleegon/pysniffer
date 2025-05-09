import time
import traceback
from threading import Lock
from collections import deque
from  datetime import  datetime,timedelta
import numpy as np
import pyqtgraph as pg
from PyQt5 import QtWidgets
from PyQt5.QtCore import QThread, QTimer
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QTabWidget, QListWidget, QLabel, QTextEdit, QHBoxLayout, \
    QLineEdit, QPushButton, QFileDialog, QProgressBar


class TrafficAnalyzerGUI(QMainWindow):
    base_dark = "#EBF5FC"  # 冰川蓝
    base_light = "#268F89"  # 松石绿
    def __init__(self,db_name='packet.db'):
        super().__init__()

        self.setStyleSheet(f"""
            /* 主窗口样式 */
            QMainWindow {{
                background-color: {self.base_dark};
                border: 2px solid {self.base_light};
            }}

            /* 全局基础样式 */
            QWidget {{
                color: {self.base_light};
                font-family: 'Fira Code';
                font-size: 11pt;
                selection-background-color: {self.base_light};
                selection-color: {self.base_dark};
            }}

            /* 增强型选项卡 */
            QTabWidget::pane {{
                border: 2px solid {self.base_light}55;
                border-radius: 6px;
                background: {self.base_dark};
                margin-top: -1px;
            }}
            QTabBar::tab {{
                background: {self.base_dark};
                color: {self.base_light};
                padding: 12px 24px;
                border: 2px solid transparent;
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                margin-right: 4px;
                font-weight: semibold;
            }}
            QTabBar::tab:selected {{
                background: {self.base_light}22;
                border-color: {self.base_light};
                color: {self.base_light};
                font-weight: bold;
                border-bottom: 2px solid {self.base_dark};
            }}

            /* 赛博按钮 */
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {self.base_dark}, stop:1 #B3E5D1);
                border: 2px solid {self.base_light}77;
                padding: 10px 20px;
                border-radius: 6px;
                min-width: 120px;
                font-size: 12pt;
                letter-spacing: 1px;
                transition: all 0.3s ease;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {self.base_light}33, stop:1 #1A4A2A);
                border: 2px solid {self.base_light};
                box-shadow: 0 0 12px {self.base_light}44;
            }}
            QPushButton:pressed {{
                background: {self.base_light}11;
                border: 2px solid {self.base_light}AA;
            }}

            /* 未来感输入框 */
            QLineEdit {{
                background: {self.base_dark}DD;
                border: 2px solid {self.base_light}55;
                padding: 8px 12px;
                border-radius: 6px;
                font-size: 12pt;
            }}
            QLineEdit:focus {{
                border: 2px solid {self.base_light};
                box-shadow: 0 0 15px {self.base_light}33;
            }}

            /* 数据展示增强 */
            QTextEdit, QListWidget, QTableView {{
                background: {self.base_dark}EE;
                border: 2px solid {self.base_light}33;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: {self.base_light}AA;
            }}

            /* 动态进度条 */
            QProgressBar {{
                background: {self.base_dark};
                border: 2px solid {self.base_light}55;
                border-radius: 8px;
                height: 24px;
                text-align: center;
                font-size: 12pt;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0.5, x2:1, y2:0.5,
                    stop:0 {self.base_light}, stop:1 #7BEEDF);
                border-radius: 6px;
                border: 1px solid {self.base_light}77;
            }}

            /* 科技感下拉菜单 */
            QComboBox {{
                background: {self.base_dark};
                border: 2px solid {self.base_light}55;
                padding: 8px 32px 8px 12px;
                border-radius: 6px;
                min-width: 120px;
            }}
            QComboBox::drop-down {{
                border-left: 2px solid {self.base_light}55;
                width: 30px;
            }}
            QComboBox QAbstractItemView {{
                background: {self.base_dark};
                border: 2px solid {self.base_light};
                selection-background-color: {self.base_light}33;
            }}

            /* 自定义滚动条 */
            QScrollBar:vertical {{
                background: {self.base_dark};
                width: 14px;
                border-left: 2px solid {self.base_light}88;
            }}
            QScrollBar::handle:vertical {{
                background: {self.base_light}55;
                min-height: 30px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical:hover {{
                background: {self.base_light}88;
            }}
            QMenu {{
                color: #FFFFFF;  /* 修改字体颜色（白色） */
                background-color: {self.base_dark}CC;  /* 背景色 */
                border: 2px solid {self.base_light}88;  /* 半透明边框 */
                font-family: 'Fira Code';
                padding: 8px;
            }}
            QMenu::item {{
                padding: 6px 24px;  /* 菜单项内边距 */
                border-radius: 4px;  /* 圆角 */
                margin: 2px;  /* 项间距 */
            }}
            QMenu::item:selected {{  /* 悬停/选中状态 */
                background-color: {self.base_light}33;  /* 半透明高亮 */
                border: 1px solid {self.base_light}77;  /* 发光边框 */
            }}
             QMenu::separator {{  /* 分割线样式 */
                height: 2px;
                background: {self.base_light}44;
                margin: 6px 12px;
            }}
        """)
        self.db_name = db_name
        self.lock = Lock()
        self.setWindowTitle("sniffing")
        self.setGeometry(100, 100, 1200, 800)
        self.widget = QWidget()#顶层窗口部件
        self.setCentralWidget(self.widget)
        self.layout = QVBoxLayout()#创建垂直部件排布类
        self.widget.setLayout(self.layout)
        self.current_stats = {}  # 新增：存储当前统计信息

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


        self.statistics_table = QTextEdit()#左侧统计信息
        self.statistics_table.setFont(QFont("Courier New", 9))
        self.capture_control_layout = QHBoxLayout()
        self.capture_layout = QVBoxLayout()
        self.packet_table = QTextEdit()#上方数据包详细信息
        self.packet_table.setFont(QFont("Courier New", 9))
        self.capture_layout.addWidget(self.packet_table)
        # BPF输入框
        self.bpf_input = QLineEdit()
        self.bpf_input.setPlaceholderText("输入BPF过滤规则，例如: tcp port 80")
        self.capture_control_layout.addWidget(QLabel("BPF Filter:"))
        self.capture_control_layout.addWidget(self.bpf_input)
        #开始与停止捕获按钮
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
        #导出与导入按钮
        self.import_btn = QPushButton("导入PCAP")
        self.export_btn = QPushButton("导出PCAP")
        self.capture_control_layout.addWidget(self.import_btn)
        self.capture_control_layout.addWidget(self.export_btn)

        # 捕获报告选项卡
        # 报告选项卡增强
        self.report_layout = QVBoxLayout()

        # 添加控制按钮栏
        self.report_control = QHBoxLayout()
        self.generate_report_btn = QPushButton("生成流量报告")
        self.export_report_btn = QPushButton("导出报告")
        self.clear_report_btn = QPushButton("清空报告")
        self.clear_database_btn=QPushButton("清除数据库")

        # 设置按钮样式
        for btn in [self.generate_report_btn, self.export_report_btn, self.clear_report_btn, self.clear_database_btn]:
            btn.setFixedHeight(30)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {self.base_dark};
                    border: 1px solid {self.base_light}77;
                    color: {self.base_light};
                    padding: 4px 12px;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background: {self.base_light}22;
                    border: 1px solid {self.base_light};
                }}
            """)

        self.report_control.addWidget(self.generate_report_btn)
        self.report_control.addWidget(self.export_report_btn)
        self.report_control.addWidget(self.clear_report_btn)
        self.report_control.addWidget(self.clear_database_btn)
        self.report_control.addStretch()

        # 报告显示区域增强
        self.report_text = QTextEdit()
        self.report_text.setStyleSheet(f"""
            QTextEdit {{
                background: {self.base_dark}EE;
                border: 2px solid {self.base_light}33;
                color: {self.base_light};  /* 使用主亮色 */
                font-family: Consolas;
                font-size: 11pt;
                line-height: 1.4;
            }}
            /* 增强标题显示 */
            h2 {{
                color: {self.base_light};
                font-size: 14pt;
                margin: 15px 0;
            }}
            /* 增强数据项显示 */
            .data-item {{
                margin: 8px 0;
                padding-left: 20px;
                border-left: 3px solid {self.base_light}77;
            }}
        """)

        # 布局组装
        self.report_layout.addLayout(self.report_control)
        self.report_layout.addWidget(self.report_text)
        self.report_tab.setLayout(self.report_layout)

        # 信号连接
        self.generate_report_btn.clicked.connect(self.generate_flow_report)
        self.export_report_btn.clicked.connect(self.export_report)
        self.clear_report_btn.clicked.connect(self.clear_report)
        self.clear_database_btn.clicked.connect(self.clear_database)
        self.import_btn.clicked.connect(self._handle_pcap_import)
        self.export_btn.clicked.connect(self._handle_pcap_export)

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
        self.chart_selector.addItems(["网络层", "传输层", "应用层","流量趋势"])
        self.capture_control_layout.addWidget(QLabel("显示图表:"))
        self.capture_control_layout.addWidget(self.chart_selector)
        # 创建三个饼图并共享同一显示区域
        self.chart_widget = pg.GraphicsLayoutWidget()
        self.chart_widget.setBackground('#EBF5FC')

        self.chart_selector.currentIndexChanged.connect(self.handle_chart_selection_change)

        # 创建三个饼图但默认隐藏两个
        self.network_plot = self.create_pie_chart("网络层协议分布")
        self.transport_plot = self.create_pie_chart("传输层协议分布")
        self.application_plot = self.create_pie_chart("应用层协议分布")

        # 初始只显示网络层
        self.transport_plot.hide()
        self.application_plot.hide()
        self.chart_widget.addItem(self.network_plot)
        # 创建流量趋势曲线图
        self.traffic_plot = self.create_traffic_plot()
        self.traffic_plot.hide()
        # 流量数据缓存
        self.traffic_cache = {
            'data': [],
            'last_update': time.time()
        }

        # 将图表添加到布局
        self.chart_widget.addItem(self.network_plot)
        self.chart_widget.addItem(self.transport_plot)
        self.chart_widget.addItem(self.application_plot)

        #添加图例
        self._init_legends()

        # 将组件添加到容器
        self.stats_layout.addWidget(self.statistics_table)# 左侧统计文本
        self.stats_layout.addWidget(self.chart_widget)

        # 将统计容器添加到主布局
        self.capture_layout.addWidget(self.stats_container)

        # 创建进度条组件
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)  # 默认隐藏

        # 将进度条添加到状态栏
        self.statusBar().addPermanentWidget(self.progress_bar)
        #优化性能
        self.packet_buffer = []#双缓冲技术
        self.packet_timer = QTimer()
        self.packet_timer.timeout.connect(self.flush_packet_buffer)
        self.packet_timer.start(32)  # 32毫秒刷新一次
        # 在所有图表中启用OpenGL加速
        pg.setConfigOptions(useOpenGL=True, enableExperimental=True)

        # 设置抗锯齿提升显示质量
        pg.setConfigOptions(antialias=True)

    def create_pie_chart(self, title):
        """创建单个饼图的基础配置"""
        pg.setConfigOption('background', self.base_dark)
        pg.setConfigOption('foreground', self.base_light)

        plot = self.chart_widget.addPlot(title=title)
        plot.getAxis('left').setPen(pg.mkPen(color=self.base_light, width=2))#左坐标线
        plot.getAxis('bottom').setPen(pg.mkPen(color=self.base_light, width=2))#下方坐标线
        # 启用OpenGL加速
        plot.useOpenGL = True

        # 创建渐变填充效果
        colormap = pg.ColorMap(
            pos=[0, 1],
            color=[
                pg.mkColor(self.base_light + '55'),  # 带透明度
                pg.mkColor(self.base_light)
            ]
        )

        # 正确设置颜色映射
        gradient = pg.GradientEditorItem(orientation='right')
        gradient.setColorMap(colormap)  # 只需传入一个参数

        # 动态光效装饰
        decoration = pg.PlotCurveItem(pen=pg.mkPen(color=self.base_light + '55', width=3))
        plot.addItem(decoration)

        return plot

    def create_traffic_plot(self):
        """创建使用OpenGL加速的流量趋势图"""
        plot = self.chart_widget.addPlot(title="流量趋势分析")
        plot.useOpenGL = True

        # 设置坐标轴样式
        plot.setLabel('left', '流量', units='B/s')
        plot.setLabel('bottom', '时间')
        plot.showGrid(x=True, y=True, alpha=0.3)
        plot.setLimits(xMin=0, yMin=0)

        # 创建曲线项
        self.traffic_curve = plot.plot(
            pen=pg.mkPen(color='#4ECDC4', width=2),
            fillLevel=0,
            brush=(78, 205, 196, 50)
        )

        # 初始化数据缓存
        self.traffic_data = {
            'timestamps': deque(maxlen=300),  # 保存5分钟数据（300秒）
            'bytes': deque(maxlen=300)
        }

        # 设置定时刷新
        self.traffic_timer = QTimer()
        self.traffic_timer.timeout.connect(self.update_traffic_plot)
        self.traffic_timer.start(1000)  # 每秒更新

        return plot

    def update_traffic_plot(self):
        """更新流量趋势图"""
        now = datetime.now()
        start_time = now - timedelta(seconds=300)  # 获取最近5分钟数据

        try:
            # 从数据库获取数据
            rates = self.db_manager.get_traffic_rates(
                start_time=start_time,
                end_time=now,
                resolution='second'
            )

            # 处理数据
            timestamps = []
            byte_rates = []
            for time_str, bytes_val in rates:
                try:
                    ts = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S").timestamp()#将字符串转化为时间元组
                    timestamps.append(ts)
                    byte_rates.append(bytes_val)
                except:
                    continue

            # 转换为numpy数组提升性能，可利用numpy特有函数
            if len(timestamps) > 0:
                x = np.array(timestamps)
                y = np.array(byte_rates)

                # 转换为相对时间（秒）
                x = x - x[0]

                self.traffic_curve.setData(
                    x=x,
                    y=y,
                    _callSync='off'  # 异步更新提升性能
                )
        except Exception as e:
            print(f"更新流量图失败: {str(e)}")
    def refresh_interface_list(self):
        """更新接口列表"""
        self.interface_list.clear()
        for idx, iface in enumerate(self.interfaces, 1):
            item_text = f"{idx:2} | {iface['name'][:20]:20} | {iface['type']:8} | " \
                        f"{iface['status']:8} | {iface['description'][:15]}..."
            self.interface_list.addItem(item_text)

    def select_interface(self, item):
        """选择接口，利用接口前面的数字判断"""
        idx = int(item.text().split('|')[0].strip()) - 1
        if 0 <= idx < len(self.interfaces):
            self.selected_iface = self.interfaces[idx]
            print(f"Selected interface: {self.selected_iface}")

    def start_capture(self):
        """开始捕获"""
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
        """停止捕获"""
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
        self.handle_chart_selection_change()

    def display_packet(self, packet_info):
        summary = self.format_packet_summary(packet_info)
        self.packet_table.append(summary)
        self.packet_table.verticalScrollBar().setValue(self.packet_table.verticalScrollBar().maximum())
        self.packet_buffer.append(packet_info)
        if len(self.packet_buffer) > 100:  # 防止内存溢出
            self.flush_packet_buffer()

    def display_statistics(self, stats):
        self.current_stats = stats.copy()  # 保存统计信息
        # 保存统计信息（如果传入空值则使用当前）
        self.current_stats = stats or self.current_stats
        # 清空显示区域
        self.statistics_table.clear()
        from PyQt5.QtGui import QFont
        self.statistics_table.setFont(QFont("Courier New", 9))
        self.statistics_table.append("-- 网络接口层 --")
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
        self.traffic_plot.hide()

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
        elif chart_type == "流量趋势":
            self.traffic_plot.show()
            # 初始化时隐藏其他图例
            for legend in self.legends.values():
                legend.hide()

    def format_packet_summary(self, packet_info):
        layers = packet_info.get('layer_hierarchy', '').split('/')#分层
        metadata = packet_info.get('metadata', {})#元数据

        # 协议显示优化（显示所有应用层协议或最高层协议）
        app_layer_identifiers = {'HTTP', 'HTTPS', 'DNS', 'FTP', 'SSH', 'SIP'}
        app_protocols = [layer for layer in layers if layer in app_layer_identifiers]

        if app_protocols:
            proto_display = " → ".join(app_protocols)#有应用层协议就是应用层协议没有就最高
        else:
            proto_display = layers[-1] if layers else 'L2-Frame'  # 修改点

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
        #DNS信息
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
        cache_key = hash((tuple(labels), tuple(values)))#将标签和值都元组化，并进行哈希处理
        if hasattr(plot, '_cache_key') and plot._cache_key == cache_key:
            return#与现有对比，若相同则不重绘

        """更新单个饼图"""
        plot.clear()

        # 过滤零值
        valid_data = [(l, v, c) for l, v, c in zip(labels, values, colors) if v > 0]#数据是元组化后放到列表当中
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
                text_y = -1.2 * np.sin(mid_angle)

                text = pg.TextItem(
                    f"{label}\n{value / total:.1%}",
                    color='k',
                    anchor=(0.5, 0.5),
                    border='w',
                    fill=(235, 245, 252, 100)
                )
                text.setPos(text_x, text_y)
                text.setZValue(100)  # 高层级
                graphics_items.append(text)

        # 创建扇形（后）
            wedge = pg.QtWidgets.QGraphicsPathItem()# 创建扇形图形项
            radius = 0.8#定义饼图半径
            path = pg.QtGui.QPainterPath()#核心绘图操作容器
            path.moveTo(0, 0)#移到原点
            path.arcTo(-radius, -radius, radius * 2, radius * 2, start_angle, end_angle - start_angle)
            path.lineTo(0, 0)
            wedge.setPath(path)# 将构建好的路径设置给图形项
            wedge.setBrush(pg.mkBrush(color))
            wedge.setPen(pg.mkPen('k', width=1))
            wedge.setZValue(10)  # 低层级
            graphics_items.append(wedge)

            start_angle = end_angle

        # 批量添加图形项（保持添加顺序）
        for item in graphics_items:
            plot.addItem(item)
        plot._cache_key = cache_key  # 存储当前数据指纹

    def _init_legends(self):
        """预创建所有图例并设置初始隐藏"""
        # 定义各层图例参数
        legend_config = {
            'network': {
                'labels': ['IPv4', 'IPv6', 'ARP', 'ICMP'],
                'colors': ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'],  # 4色
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
                text_item.setText(label, color=self.base_light)
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
        options = QFileDialog.Options()#获取文件路径的类
        path, _ = QFileDialog.getSaveFileName(
            self, "保存报告", "",
            "文本文件 (*.txt)",
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
    def clear_database(self):
        self.db_manager.cleanup_old_records(days=0)
        self.statusBar().showMessage("数据库已清空", 3000)


    def get_all_raw_packets(self):
        """获取所有原始数据包字节"""
        with self.lock:
            import sqlite3
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()#创造游标（返回结果的接口，将查到的结果存起来沿着游标一个一个取出来）
                cursor.execute("SELECT raw_data FROM packets WHERE raw_data IS NOT NULL")
                return [row[0] for row in cursor.fetchall()]

    def _handle_pcap_import(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "选择PCAP文件", "", "PCAP文件 (*.pcap *.pcapng)")
        if path:
            self.progress_bar.show()
            from core.pcapworker import PCAPWorker
            self.worker = PCAPWorker(self.db_manager, 'import', path)
            self.worker.progress.connect(self.progress_bar.setValue)
            self.worker.finished.connect(self._on_pcap_finished)
            self.worker.start()

    def _handle_pcap_export(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "保存PCAP文件", "", "PCAP文件 (*.pcap)")
        if path:
            self.progress_bar.show()
            from core.pcapworker import PCAPWorker
            self.worker = PCAPWorker(self.db_manager, 'export', path)
            self.worker.progress.connect(self.progress_bar.setValue)
            self.worker.finished.connect(self._on_pcap_finished)
            self.worker.start()

    def _on_pcap_finished(self, success, message):
        self.progress_bar.hide()
        self.statusBar().showMessage(message, 5000)
        if success:
            self._refresh_after_import()  # 导入后刷新数据

    def _refresh_after_import(self):
        """导入后刷新界面数据"""
        # 刷新数据包列表
        self.packet_table.clear()

        # 获取最新统计信息
        stats = self.db_manager.get_protocol_stats()

        # 根据当前选择的图表类型更新
        chart_type = self.chart_selector.currentText()

        if chart_type == "网络层":
            self.update_pie_chart(
                plot=self.network_plot,
                labels=['IPv4', 'IPv6', 'ARP', 'ICMP'],
                values=[
                    stats['network'].get('IPv4', 0),
                    stats['network'].get('IPv6', 0),
                    stats['network'].get('ARP', 0),
                    stats['network'].get('ICMP', 0)
                ],
                colors=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
            )
        elif chart_type == "传输层":
            self.update_pie_chart(
                plot=self.transport_plot,
                labels=['TCP', 'UDP'],
                values=[
                    stats['transport'].get('TCP', 0),
                    stats['transport'].get('UDP', 0)
                ],
                colors=['#FF6B6B', '#4ECDC4']
            )
        elif chart_type == "应用层":
            self.update_pie_chart(
                plot=self.application_plot,
                labels=['HTTP', 'DNS', 'HTTPS', 'SIP', 'FTP', 'SMTP', 'POP3', 'IMAP'],
                values=[
                    stats['application'].get('HTTP', 0),
                    stats['application'].get('DNS', 0),
                    stats['application'].get('HTTPS', 0),
                    stats['application'].get('SIP', 0),
                    stats['application'].get('FTP', 0),
                    stats['application'].get('SMTP', 0),
                    stats['application'].get('POP3', 0),
                    stats['application'].get('IMAP', 0)
                ],
                colors=['#4B8BBE', '#F7B267', '#7FB069', '#D64550',
                        '#6C5B7B', '#5C9EAD', '#F4D35E', '#E56399']
            )

        # 刷新统计显示
        self.display_statistics(stats)

    def handle_chart_selection_change(self):
        """当用户切换图表类型时触发更新"""
        if not self.current_stats:
            return

        # 复用原有显示统计的逻辑
        self.display_statistics(self.current_stats)

    def flush_packet_buffer(self):
        """ 批量刷新数据包显示 """
        if not hasattr(self, 'packet_buffer') or not self.packet_buffer:#包含缓冲区属性且缓冲区不为空
            return

        # 创建临时QTextDocument处理HTML
        doc = self.packet_table.document()#获取文档
        cursor = self.packet_table.textCursor()

        # 移动到文档末尾
        cursor.movePosition(cursor.End)

        # 拼接HTML内容
        html_content = "<br>".join(
            f"<pre>{self.format_packet_summary(packet)}</pre>"
            for packet in self.packet_buffer
        )

        # 插入HTML并自动滚动
        cursor.insertHtml(html_content + "<br>")
        self.packet_buffer.clear()

        # 滚动到底部
        self.packet_table.ensureCursorVisible()


