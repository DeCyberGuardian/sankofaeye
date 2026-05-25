"""
SankofahEye — Logger
AfriWealth Cyber Intelligence
"""

import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class SankofahLogger:
    LEVEL_COLORS = {
        "DEBUG":    Fore.CYAN,
        "INFO":     Fore.GREEN,
        "WARNING":  Fore.YELLOW,
        "ERROR":    Fore.RED,
        "CRITICAL": Fore.MAGENTA,
    }

    def __init__(self, name: str, log_dir: str = "logs", level: str = "INFO"):
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"sankofaeye_{timestamp}.log")

        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        # File handler (plain text)
        fh = logging.FileHandler(log_file)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
        ))
        self.logger.addHandler(fh)

    def _print(self, level: str, msg: str):
        color = self.LEVEL_COLORS.get(level, "")
        prefix = f"[{level}]"
        print(f"{color}{prefix:<10}{Style.RESET_ALL} {msg}")

    def info(self, msg: str):
        self.logger.info(msg)
        self._print("INFO", msg)

    def debug(self, msg: str):
        self.logger.debug(msg)
        self._print("DEBUG", msg)

    def warning(self, msg: str):
        self.logger.warning(msg)
        self._print("WARNING", msg)

    def error(self, msg: str):
        self.logger.error(msg)
        self._print("ERROR", msg)

    def critical(self, msg: str):
        self.logger.critical(msg)
        self._print("CRITICAL", msg)

    def banner(self, target: str, version: str):
        print(f"\n{Fore.CYAN}{'═' * 60}")
        print(f"  SankofahEye — AfriWealth Cyber Intelligence")
        print(f"  Version : {version}")
        print(f"  Target  : {target}")
        print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'═' * 60}{Style.RESET_ALL}\n")
