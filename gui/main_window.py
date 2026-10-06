"""Главное окно AegisScan с боковой навигацией, треем и резидентной защитой."""
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QPushButton, QStackedWidget, QButtonGroup,
    QMessageBox, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QCloseEvent

from gui.styles import DARK_THEME
from gui.tray_icon import TrayIcon
from gui.pages.home_page import HomePage
from gui.pages.scan_page import ScanPage
from gui.pages.chat_page import ChatPage
from gui.pages.quarantine_page import QuarantinePage
from gui.pages.journal_page import JournalPage
from gui.pages.settings_page import SettingsPage
from core import resident, journal


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AegisScan — антивирус с ИИ")
        self.setMinimumSize(900, 600)
        self.setStyleSheet(DARK_THEME)

        self.stats = {"scanned": 0, "threats": 0}
        self.protector = None
        self.allow_close = False
        self.minimize_to_tray = True

        self._build_ui()
        self._setup_tray()
        self._start_protection()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Верхняя панель
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

        # Основная область
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

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

        version = QLabel("v0.5.0")
        version.setStyleSheet("color: #585b70; font-size: 11px; padding: 10px;")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(version)

        body.addWidget(sidebar)

        self.stack = QStackedWidget()

        self.home_page = HomePage()
        self.scan_page = ScanPage()
        self.quarantine_page = QuarantinePage()
        self.journal_page = JournalPage()
        self.chat_page = ChatPage()
        self.settings_page = SettingsPage()

        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.scan_page)
        self.stack.addWidget(self.quarantine_page)
        self.stack.addWidget(self.journal_page)
        self.stack.addWidget(self.chat_page)
        self.stack.addWidget(self.settings_page)

        body.addWidget(self.stack, 1)
        root_layout.addLayout(body)

        self.home_page.scan_requested.connect(self._go_to_scan)
        self.home_page.protection_toggled.connect(self._on_protection_toggled)
        self.scan_page.scan_completed.connect(self._on_scan_completed)

        self.nav_buttons[0].setChecked(True)
        self.stack.setCurrentIndex(0)

    def _setup_tray(self):
        self.tray = TrayIcon(self)
        self.tray.show_window_requested.connect(self._restore_window)
        self.tray.quit_requested.connect(self._quit_app)
        self.tray.show()

    def _start_protection(self):
        if self.protector is not None and self.protector.isRunning():
            return
        try:
            self.protector = resident.ResidentProtector()
            self.protector.threat_detected.connect(self._on_threat)
            self.protector.scan_result.connect(self._on_resident_scan)
            self.protector.start()
            self.home_page.set_protection_state(True)
            self.tray.set_protection_state(True)
            journal.add_event("startup", "AegisScan", "", "clean", "System",
                              "Резидентная защита запущена")
        except Exception as e:
            print(f"[Main] Ошибка запуска защиты: {e}")

    def _stop_protection(self):
        if self.protector is not None:
            try:
                self.protector.stop()
            except Exception as e:
                print(f"[Main] Ошибка остановки: {e}")
            self.protector = None
        journal.add_event("startup", "AegisScan", "", "clean", "System",
                          "Резидентная защита остановлена")

    def _on_protection_toggled(self, enabled: bool):
        if enabled:
            self._start_protection()
            self._set_status("Защита активна", "ok")
            self.tray.set_protection_state(True)
        else:
            self._stop_protection()
            self._set_status("Защита отключена", "warning")
            self.tray.set_protection_state(False)

    def _on_threat(self, info: dict):
        name = info.get("name", "—")
        self.stats["threats"] += 1
        self.stats["scanned"] += 1
        self.home_page.update_stats(self.stats["scanned"], self.stats["threats"])
        self._set_status("Обнаружена угроза", "danger")

        self.tray.notify(
            "🚨 AegisScan — Обнаружена угроза",
            f"{name}\nФайл помещён в карантин",
        )

    def _on_resident_scan(self, result: dict):
        self.stats["scanned"] += 1
        self.home_page.update_stats(self.stats["scanned"], self.stats["threats"])

    def _switch_page(self, index: int):
        self.stack.setCurrentIndex(index)
        self.nav_buttons[index].setChecked(True)

        if index == 2:
            try:
                self.quarantine_page.refresh()
            except Exception:
                pass
        elif index == 3:
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

    def _restore_window(self):
        self.showNormal()
        self.activateWindow()
        self.raise_()

    def _quit_app(self):
        self.allow_close = True
        self._stop_protection()
        try:
            self.tray.hide()
        except Exception:
            pass
        QApplication.quit()

    def closeEvent(self, event: QCloseEvent):
        if self.allow_close:
            if self.protector is not None:
                try:
                    self.protector.stop()
                except Exception:
                    pass
            event.accept()
            return

        if self.minimize_to_tray:
            event.ignore()
            self.hide()
            try:
                self.tray.notify(
                    "AegisScan",
                    "Приложение свёрнуто в трей. Защита продолжает работу.",
                )
            except Exception:
                pass
        else:
            self.allow_close = True
            self._stop_protection()
            event.accept()