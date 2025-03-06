import sys
import logging
import threading
import re  # 新增正则表达式支持


class WarningFilter:
    def __init__(self, patterns=None, log_file=None, suppress_pillow_warnings=False):
        self.original_stderr = sys.stderr
        self.filter_patterns = set(patterns or [])
        self.log_file = log_file
        self.lock = threading.Lock()

        # 动态添加正则表达式模式（更灵活）
        if suppress_pillow_warnings:
            self.filter_patterns.add(re.compile(r"(libpng|iCCP:).*incorrect sRGB profile"))
        else:
            self.filter_patterns = {re.compile(p) if isinstance(p, str) else p for p in self.filter_patterns}

        # 配置日志
        if self.log_file:
            logging.basicConfig(
                filename=self.log_file,
                level=logging.WARNING,
                format='%(asctime)s - %(message)s',
                filemode='a'
            )

    def __enter__(self):
        sys.stderr = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stderr = self.original_stderr

    def write(self, text):
        # 检查是否匹配任一正则表达式
        if not any(pattern.search(text) for pattern in self.filter_patterns):
            self.original_stderr.write(text)
        elif self.log_file:
            logging.warning(text.strip())

    def flush(self):
        self.original_stderr.flush()
