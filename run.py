#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetSentry 启动脚本
"""

import sys
import os

project_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_dir)

os.environ['QT_ENABLE_HIGHDPI_SCALING'] = '1'
os.environ['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'
os.environ['QT_SCALE_FACTOR_ROUNDING_POLICY'] = 'RoundPreferFloor'

from PyQt6.QtWidgets import QApplication
from PyQt6.QtGui import QFont
from ui.main_window import NetSentryWindow


def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    font = QFont("Microsoft YaHei UI", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)
    
    window = NetSentryWindow()
    window.show()
    
    sys.exit(app.exec())


if __name__ == "__main__":
    main()