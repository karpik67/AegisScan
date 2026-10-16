"""Страница сканера браузеров."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QPushButton
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from core import browser_scanner


CARD_OK_QSS = """
QFrame#browserCard {
    background-color: #1e3a2f;
    border: 2px solid #28a745;
    border-radius: 12px;
}
"""

CARD_WARN_QSS = """
QFrame#browserCard {
    background-color: #3a2f1e;
    border: 2px solid #f9a825;
    border-radius: 12px;
}
"""

CARD_DANGER_QSS = """
QFrame#browserCard {
    background-color: #3a1e1e;
    border: 2px solid #dc3545;
    border-radius: 12px;
}
"""

TABLE_QSS = """
QTableWidget {
    background-color: #181825;
    color: #cdd6f4;
    border: 1px solid #363a4f;
    border-radius: 8px;
    gridline-color: #313244;
    font-size: 12px;
}
QTableWidget::item {
    padding: 6px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #313244;
    color: #89b4fa;
}
QHeaderView::section {
    background-color: #24273a;
    color: #89b4fa;
    padding: 8px;
    border: none;
    border-bottom: 1px solid #363a4f;
    font-weight: 600;
}
"""


class LoadWorker(QThread):
    finished = pyqtSignal(list, dict)

    def run(self):
        exts = browser_scanner.get_extensions()
        proxy = browser_scanner.get_proxy_settings()
        self.finished.emit(exts, proxy)


class BrowserPage(QWidget):
    def __init__(self):
        super().__init__()
        self.extensions = []
        self.proxy = {}
        self.loader = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 30, 30, 30)
        root.setSpacing(15)

        head = QHBoxLayout()
        title = QLabel("🌍  Браузеры")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        head.addWidget(title)
        head.addStretch()

        self.count_label = QLabel("0 расширений")
        self.count_label.setStyleSheet(
            "color: #7f849c; font-size: 13px;"
        )
        head.addWidget(self.count_label)
        root.addLayout(head)

        subtitle = QLabel(
            "Расширения и настройки прокси в Chrome, Edge, Brave, Firefox"
        )
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # Карточка прокси
        self.proxy_card = QFrame()
        self.proxy_card.setObjectName("browserCard")
        self.proxy_card.setMinimumHeight(80)

        proxy_layout = QHBoxLayout(self.proxy_card)
        proxy_layout.setContentsMargins(20, 15, 20, 15)
        proxy_layout.setSpacing(15)

        self.proxy_icon = QLabel("🌐")
        self.proxy_icon.setStyleSheet("font-size: 32px; background: transparent;")
        self.proxy_icon.setFixedWidth(50)
        proxy_layout.addWidget(self.proxy_icon)

        proxy_info = QVBoxLayout()
        proxy_info.setSpacing(3)

        self.proxy_title = QLabel("НАСТРОЙКИ ПРОКСИ")
        self.proxy_title.setStyleSheet(
            "color: white; font-size: 13px; font-weight: 600; "
            "background: transparent;"
        )
        proxy_info.addWidget(self.proxy_title)

        self.proxy_status = QLabel("Проверка...")
        self.proxy_status.setStyleSheet(
            "color: rgba(255,255,255,0.8); font-size: 12px; "
            "background: transparent;"
        )
        self.proxy_status.setWordWrap(True)
        proxy_info.addWidget(self.proxy_status)

        proxy_layout.addLayout(proxy_info, 1)
        root.addWidget(self.proxy_card)

        # Кнопка
        btn_row = QHBoxLayout()
        self.btn_refresh = QPushButton("🔄  Обновить")
        self.btn_refresh.setMinimumHeight(36)
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh)
        btn_row.addWidget(self.btn_refresh)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # Статус
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(
            "color: #89b4fa; font-size: 12px;"
        )
        root.addWidget(self.status_label)

        # Таблица
        self.table = QTableWidget()
        self.table.setStyleSheet(TABLE_QSS)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Браузер", "Название", "Версия", "Разрешений",
            "Профиль", "Причина"
        ])
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)

        self.table.setColumnWidth(0, 90)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 100)
        self.table.setColumnWidth(4, 110)
        self.table.setColumnWidth(5, 280)

        root.addWidget(self.table, 1)

    def refresh(self):
        self.status_label.setText("Загрузка расширений...")
        self.btn_refresh.setEnabled(False)

        self.loader = LoadWorker()
        self.loader.finished.connect(self._on_loaded)
        self.loader.start()

    def _on_loaded(self, exts: list, proxy: dict):
        self.extensions = exts
        self.proxy = proxy

        self._render_proxy(proxy)
        self._populate(exts)

        self.btn_refresh.setEnabled(True)

        sus = sum(1 for e in exts if e["suspicious"])
        self.count_label.setText(
            f"{len(exts)} расширений · подозрительных: {sus}"
        )
        self.status_label.setText(
            f"Найдено {len(exts)} расширений. Подозрительных: {sus}"
        )

    def _render_proxy(self, proxy: dict):
        if proxy.get("suspicious"):
            self.proxy_card.setStyleSheet(CARD_DANGER_QSS)
            self.proxy_icon.setText("🚨")
            reasons = "; ".join(proxy.get("reasons", []))
            self.proxy_status.setText(reasons or "Подозрительные настройки")
        elif proxy.get("enabled"):
            self.proxy_card.setStyleSheet(CARD_WARN_QSS)
            self.proxy_icon.setText("⚠️")
            self.proxy_status.setText(
                f"Прокси включён: {proxy.get('server', '—')}"
            )
        else:
            self.proxy_card.setStyleSheet(CARD_OK_QSS)
            self.proxy_icon.setText("✅")
            self.proxy_status.setText(
                "Прокси не используется — настройки безопасны"
            )

    def _populate(self, exts: list):
        self.table.setRowCount(len(exts))

        for row, e in enumerate(exts):
            item_browser = QTableWidgetItem(e["browser"])
            item_browser.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_name = QTableWidgetItem(e["name"])
            item_ver = QTableWidgetItem(e["version"])
            item_ver.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_perms = QTableWidgetItem(str(e["permissions"]))
            item_perms.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_profile = QTableWidgetItem(e["profile"])
            item_profile.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            reason = "; ".join(e.get("reasons", [])) or "—"
            item_reason = QTableWidgetItem(reason)

            if e["suspicious"]:
                red = QColor("#3a1e1e")
                for w in [item_browser, item_name, item_ver,
                          item_perms, item_profile, item_reason]:
                    w.setBackground(red)
                item_name.setForeground(QColor("#ff6b6b"))

            self.table.setItem(row, 0, item_browser)
            self.table.setItem(row, 1, item_name)
            self.table.setItem(row, 2, item_ver)
            self.table.setItem(row, 3, item_perms)
            self.table.setItem(row, 4, item_profile)
            self.table.setItem(row, 5, item_reason)