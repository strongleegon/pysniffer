from datetime import datetime
from core.database import DatabaseManager


class ReportGenerator:
    """报告生成核心类，支持多种分析报告类型"""

    def __init__(self, db_manager:DatabaseManager  ):
        """
        初始化报告生成器（依赖注入模式）
        """
        self.db = db_manager
        self._report_cache = None  # 示例状态维护

    def generate_flow_report(self) -> str:
        """增强版流量分析报告"""
        report = "=== 流量分析报告 ===\n"
        report += f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

        try:
            time_range = self.db.get_time_range()
            report += f"\n🕒 捕获时间范围：{time_range['first']} 至 {time_range['last']}"
            report += f"\n📦 总流量：{self._format_bytes(self.db.get_total_traffic())}"

            # 获取分层协议统计
            protocol_stats = self.db.get_protocol_stats()

            # 网络层协议数量
            report += "\n\n--- 网络层协议统计 ---"
            report += self._generate_protocol_table(
                protocols=[
                    ('IPv4', '🌐 IPv4'),
                    ('IPv6', '🌐 IPv6'),
                    ('ARP', '🔗 ARP'),
                    ('ICMP', '📡 ICMP')
                ],
                stats=protocol_stats['network']
            )
            report += f"\n    🔢 网络层头总大小: {self._format_bytes(self.db.get_traffic_breakdown()['headers']['ip'])}"

            # 传输层协议数量
            report += "\n\n--- 传输层协议统计 ---"
            report += self._generate_protocol_table(
                protocols=[
                    ('TCP', '🔒 TCP'),
                    ('UDP', '📨 UDP')
                ],
                stats=protocol_stats['transport']
            )
            report += f"\n    🔢 传输层头总大小: {self._format_bytes(self.db.get_traffic_breakdown()['headers']['transport'])}"

            # 应用层协议数量
            report += "\n\n--- 应用层协议统计 ---"
            report += self._generate_protocol_table(
                protocols=[
                    ('HTTP', '🌍 HTTP'),
                    ('HTTPS', '🔐 HTTPS'),
                    ('DNS', '📡 DNS'),
                    ('FTP', '📁 FTP'),
                    ('SMTP', '📧 SMTP')
                ],
                stats=protocol_stats['application']
            )
            report += f"\n    🔢 应用负载总大小: {self._format_bytes(self.db.get_traffic_breakdown()['payload'])}"
            # 新增TOP IP
            top_ips = self.db.get_top_ips()
            report += "\n\n--- 活跃IP TOP5 ---"
            for ip, count in top_ips[:5]:
                report += f"\n{ip}: {count} 次通信"
            self._report_cache = report
        except Exception as e:
            report += f"\n❌ 报告生成失败：{str(e)}"
        return report

    def _generate_protocol_table(self, protocols, stats):
        """生成协议统计表格"""
        table = "\n┌──────────────┬──────────┐"
        table += "\n│ 协议类型     │ 数量     │"
        table += "\n├──────────────┼──────────┤"

        total = 0
        for key, label in protocols:
            count = stats.get(key, 0)
            total += count
            table += f"\n│ {label:<12} │ {count:<8} │"

        table += "\n├──────────────┼──────────┤"
        table += f"\n│ 总计         │ {total:<8} │"
        table += "\n└──────────────┴──────────┘"
        return table



    def _format_bytes(self, size):
        """智能格式化字节单位"""
        units = ['B', 'KB', 'MB', 'GB']
        index = 0
        while size >= 1024 and index < 3:
            size /= 1024
            index += 1
        return f"{size:.2f} {units[index]}"