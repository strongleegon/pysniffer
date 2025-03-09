import logging
import re
import sys
import threading


class WarningFilter:
    def __init__(self, patterns=None, log_file=None, suppress_pillow_warnings=False):
        self.original_stderr = sys.stderr
        self.filter_patterns = set()
        self.log_file = log_file
        self.lock = threading.Lock()

        # 确保所有模式都是编译后的正则对象
        if patterns:
            for p in patterns:
                self._add_pattern(p)

        if suppress_pillow_warnings:
            self._add_pattern(r"(libpng|iCCP:).*incorrect sRGB profile")

        # 配置日志
        if self.log_file:
            logging.basicConfig(
                filename=self.log_file,
                level=logging.WARNING,
                format='%(asctime)s - %(message)s',
                filemode='a'
            )

    def _add_pattern(self, pattern):
        """统一处理正则表达式输入"""
        try:
            compiled = re.compile(pattern) if isinstance(pattern, str) else pattern
            self.filter_patterns.add(compiled)
        except (TypeError, re.error) as e:
            sys.stderr.write(f"Invalid regex pattern: {pattern} ({str(e)})\n")

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
