"""Страница журнала событий."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QScrollArea, QMessageBox, QFileDialog
)
from PyQt6.QtCore import Qt
from core import journal


CARD_QSS = """
QFrame#jCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
    border-radius: 10px;
}
"""

SCROLL_QSS = """
QScrollArea { background-color: transparent; border: none; }
QScrollArea > QWidget > QWidget { background-color: transparent; }
"""

VERDICT_ICONS = {
    "malware": ("🚨", "#dc3545"),
    "suspicious": ("⚠️", "#f9a825"),
    "clean": ("✅", "#28a745"),
    "quarantined": ("🗄️", "#89b4fa"),
    "error": ("⚠️", "#f9a825"),
}

EVENT_LABELS = {
    "scan": "Проверка",
    "quarantine": "Изоляция",
    "restore": "Восстановление",
    "delete": "Удаление",
    "startup": "Запуск",
    "test": "Тест",
}


class JournalEntry(QFrame):
    """Карточка одной записи журнала."""

    def __init__(self, event: dict):
        super().__init__()
        self.setObjectName("jCard")
        self.setStyleSheet(CARD_QSS)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(14)

        # Иконка вердикта
        verdict = event.get("verdict") or "clean"
        icon, color = VERDICT_ICONS.get(verdict, ("ℹ️", "#7f849c"))

        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 22px;")
        icon_lbl.setFixedWidth(34)
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_lbl)

        # Основная информация
        info = QVBoxLayout()
        info.setSpacing(3)

        name = event.get("object_name") or "—"
        ev_type = EVENT_LABELS.get(event.get("event_type", ""), 
                                    event.get("event_type", "—"))

        top = QLabel(f"{name}")
        top.setStyleSheet(
            "color: #cdd6f4; font-size: 14px; font-weight: 600;"
        )
        info.addWidget(top)

        sub = QLabel(
            f"{ev_type}  ·  {event.get('source') or '—'}"
        )
        sub.setStyleSheet("color: #7f849c; font-size: 12px;")
        info.addWidget(sub)

        if event.get("details"):
            d = QLabel(event["details"])
            d.setStyleSheet("color: #585b70; font-size: 11px;")
            d.setWordWrap(True)
            info.addWidget(d)

        layout.addLayout(info, 1)

        # Дата
        ts = event.get("timestamp", "")
        if ts:
            ts = ts.replace("T", " ")
        date_lbl = QLabel(ts)
        date_lbl.setStyleSheet(
            "color: #7f849c; font-size: 11px; padding-left: 10px;"
        )
        date_lbl.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight
        )
        layout.addWidget(date_lbl)


class JournalPage(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 30, 30, 30)
        root.setSpacing(15)

        # Заголовок
        head = QHBoxLayout()

        title = QLabel("📋  Журнал событий")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        head.addWidget(title)
        head.addStretch()

        self.stats_label = QLabel("")
        self.stats_label.setStyleSheet(
            "color: #7f849c; font-size: 13px; padding-right: 10px;"
        )
        head.addWidget(self.stats_label)

        root.addLayout(head)

        subtitle = QLabel("История всех проверок, изоляций и действий")
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # Панель кнопок
        btns = QHBoxLayout()

        self.btn_refresh = QPushButton("🔄  Обновить")
        self.btn_refresh.setMinimumHeight(38)
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh)
        btns.addWidget(self.btn_refresh)

        self.btn_export = QPushButton("💾  Экспорт в CSV")
        self.btn_export.setMinimumHeight(38)
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.clicked.connect(self._export_csv)
        btns.addWidget(self.btn_export)

        btns.addStretch()

        self.btn_clear = QPushButton("🗑  Очистить журнал")
        self.btn_clear.setMinimumHeight(38)
        self.btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear.clicked.connect(self._clear)
        btns.addWidget(self.btn_clear)

        root.addLayout(btns)

        # Скроллируемая область
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet(SCROLL_QSS)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: transparent;")

        self.entries_layout = QVBoxLayout(self.scroll_content)
        self.entries_layout.setContentsMargins(0, 5, 10, 5)
        self.entries_layout.setSpacing(8)
        self.entries_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.scroll.setWidget(self.scroll_content)
        root.addWidget(self.scroll, 1)

    # ---------- Логика ----------
    def refresh(self):
        """Перерисовывает журнал."""
        self._clear_layout()

        events = journal.get_events(limit=500)
        stats = journal.stats()

        self.stats_label.setText(
            f"Всего: {stats['total']}   ·   Угроз: {stats['threats']}   ·   "
            f"Чисто: {stats['clean']}"
        )

        if not events:
            ph = QFrame()
            ph.setObjectName("jCard")
            ph.setStyleSheet(CARD_QSS)
            ph.setMinimumHeight(240)

            ph_l = QVBoxLayout(ph)
            ph_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ph_l.setSpacing(12)

            icon = QLabel("📋")
            icon.setStyleSheet("font-size: 56px; color: #45475a;")
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

            text = QLabel("Журнал пуст")
            text.setStyleSheet("color: #7f849c; font-size: 16px;")
            text.setAlignment(Qt.AlignmentFlag.AlignCenter)

            hint = QLabel("Здесь появится история проверок файлов")
            hint.setStyleSheet("color: #585b70; font-size: 12px;")
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)

            ph_l.addWidget(icon)
            ph_l.addWidget(text)
            ph_l.addWidget(hint)

            self.entries_layout.addWidget(ph)
            return

        for event in events:
            widget = JournalEntry(event)
            self.entries_layout.addWidget(widget)

    def _clear_layout(self):
        while self.entries_layout.count():
            item = self.entries_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Экспорт журнала",
            "aegisscan_journal.csv",
            "CSV files (*.csv)"
        )
        if not path:
            return

        result = journal.export_csv(path)
        if result.get("status") == "ok":
            QMessageBox.information(
                self, "AegisScan",
                f"Экспортировано {result['count']} записей в:\n{result['path']}"
            )
        else:
            QMessageBox.warning(
                self, "Ошибка экспорта",
                result.get("message", "Неизвестная ошибка")
            )

    def _clear(self):
        stats = journal.stats()
        if stats["total"] == 0:
            QMessageBox.information(self, "AegisScan", "Журнал уже пуст.")
            return

        reply = QMessageBox.question(
            self, "Очистка журнала",
            f"Удалить все {stats['total']} записей?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        journal.clear()
        self.refresh()
        QMessageBox.information(self, "AegisScan", "Журнал очищен.")