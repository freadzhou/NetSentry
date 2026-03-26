#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSentry - 网络安全监控工具
Author: Fread.Z
Version: 1.0.0
"""

import sys
import os

# 确保能找到项目模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from ui.main_window import NetSentryWindow


def main():
    # 高DPI支持
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    
    # 设置全局字体
    font = QFont("Microsoft YaHei UI", 9)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)
    
    # 创建主窗口
    window = NetSentryWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()