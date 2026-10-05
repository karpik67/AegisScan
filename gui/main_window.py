"""Главное окно AegisScan с боковой навигацией."""
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QPushButton, QStackedWidget, QButtonGroup
)
from PyQt6.QtCore import Qt

from gui.styles import DARK_THEME
from gui.pages.home_page import HomePage
from gui.pages.scan_page import ScanPage
from gui.pages.chat_page import ChatPage
from gui.pages.quarantine_page import QuarantinePage
from gui.pages.journal_page import JournalPage
from gui.pages.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AegisScan — антивирус с ИИ")
        self.setMinimumSize(1000, 650)
        self.setStyleSheet(DARK_THEME)

        self.stats = {"scanned": 0, "threats": 0}
        self._build_ui()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ===== Верхняя панель =====
        top_bar = QFrame()
        top_bar.setStyleSheet(
            "background-color: #181825; border-bottom: 1px solid #313244;"
        )
        top_bar.setFixedHeight(55)
        top_layout = QHBoxLayout(top_bar)
        top_layout.setContentsMargins(20, 0, 20, 0)

        app_title = QLabel("🛡  AegisScan")
        app_title.setObjectName("appTitle")
        top_layout.addWidget(app_title)

        top_layout.addStretch()

        self.status_badge = QLabel("Защита активна")
        self.status_badge.setObjectName("statusBadge")
        self.status_badge.setProperty("state", "ok")
        top_layout.addWidget(self.status_badge)

        root_layout.addWidget(top_bar)

        # ===== Основная область =====
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # Сайдбар
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 15, 0, 15)
        sidebar_layout.setSpacing(2)

        self.nav_buttons = []
        self.button_group = QButtonGroup(self)
        self.button_group.setExclusive(True)

        nav_items = [
            ("🏠  Главная", 0),
            ("🔍  Сканер", 1),
            ("🗄️  Карантин", 2),
            ("📋  Журнал", 3),
            ("🤖  ИИ-помощник", 4),
            ("⚙️  Настройки", 5),
        ]

        for label, idx in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("navButton")
            btn.setCheckable(True)
            btn.setMinimumHeight(42)
            btn.clicked.connect(lambda _, i=idx: self._switch_page(i))
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)
            self.button_group.addButton(btn, idx)

        sidebar_layout.addStretch()

        version = QLabel("v0.4.0")
        version.setStyleSheet("color: #585b70; font-size: 11px; padding: 10px;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(version)

        body.addWidget(sidebar)

        # Стек страниц
        self.stack = QStackedWidget()

        self.home_page = HomePage()
        self.scan_page = ScanPage()
        self.quarantine_page = QuarantinePage()
        self.journal_page = JournalPage()
        self.chat_page = ChatPage()
        self.settings_page = SettingsPage()

        self.stack.addWidget(self.home_page)       # 0
        self.stack.addWidget(self.scan_page)       # 1
        self.stack.addWidget(self.quarantine_page) # 2
        self.stack.addWidget(self.journal_page)    # 3
        self.stack.addWidget(self.chat_page)       # 4
        self.stack.addWidget(self.settings_page)   # 5

        body.addWidget(self.stack, 1)
        root_layout.addLayout(body)

        # Связи
        self.home_page.scan_requested.connect(self._go_to_scan)
        self.scan_page.scan_completed.connect(self._on_scan_completed)

        # Первая страница
        self.nav_buttons[0].setChecked(True)
        self.stack.setCurrentIndex(0)

    def _switch_page(self, index: int):
        self.stack.setCurrentIndex(index)
        self.nav_buttons[index].setChecked(True)

        # Автообновление при переходе
        if index == 2:  # Карантин
            try:
                self.quarantine_page.refresh()
            except Exception:
                pass
        elif index == 3:  # Журнал
            try:
                self.journal_page.refresh()
            except Exception:
                pass

    def _go_to_scan(self):
        self._switch_page(1)

    def _on_scan_completed(self, result: dict):
        self.stats["scanned"] += 1
        if result.get("malicious", 0) > 0:
            self.stats["threats"] += 1

        self.home_page.update_stats(self.stats["scanned"], self.stats["threats"])

        if result.get("malicious", 0) > 0:
            self._set_status("Обнаружена угроза", "danger")
        elif result.get("status") in ("error", "timeout"):
            self._set_status("Ошибка проверки", "warning")
        else:
            self._set_status("Защита активна", "ok")

    def _set_status(self, text: str, state: str):
        self.status_badge.setText(text)
        self.status_badge.setProperty("state", state)
        self.status_badge.style().unpolish(self.status_badge)
        self.status_badge.style().polish(self.status_badge)