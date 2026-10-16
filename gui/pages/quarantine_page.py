"""Страница карантина."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QMessageBox
)
from PyQt6.QtCore import Qt
from core import quarantine
from gui.smooth_scroll import SmoothScrollArea


CARD_QSS = """
QFrame#qCard {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 12px;
}
QFrame#qCard:hover {
    border-color: #30363d;
}
"""

SCROLL_QSS = """
QScrollArea { background-color: transparent; border: none; }
QScrollArea > QWidget > QWidget { background-color: transparent; }
"""


def human_size(size: int) -> str:
    for unit in ["Б", "КБ", "МБ", "ГБ"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} ТБ"


class QuarantineItem(QFrame):
    def __init__(self, record: dict, on_delete, on_restore):
        super().__init__()
        self.setObjectName("qCard")
        self.setStyleSheet(CARD_QSS)
        self.record = record
        self.on_delete = on_delete
        self.on_restore = on_restore

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(8)

        top = QHBoxLayout()

        name = QLabel(record["filename"])
        name.setStyleSheet(
            "color: #e6edf3; font-size: 15px; font-weight: 600; "
            "background: transparent;"
        )
        top.addWidget(name)
        top.addStretch()

        size = QLabel(human_size(record["size"]))
        size.setStyleSheet(
            "color: #8b949e; font-size: 12px; background: transparent;"
        )
        top.addWidget(size)
        layout.addLayout(top)

        meta = QLabel(
            f"{record['date']}   ·   {record['source']}   ·   "
            f"{record['reason']}"
        )
        meta.setStyleSheet(
            "color: #6e7681; font-size: 12px; background: transparent;"
        )
        layout.addWidget(meta)

        path = QLabel(record["original_path"])
        path.setStyleSheet(
            "color: #484f58; font-size: 11px; background: transparent;"
        )
        path.setWordWrap(True)
        layout.addWidget(path)

        btns = QHBoxLayout()
        btns.addStretch()

        btn_restore = QPushButton("Восстановить")
        btn_restore.setMinimumHeight(32)
        btn_restore.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_restore.clicked.connect(
            lambda: self.on_restore(self.record["id"])
        )
        btns.addWidget(btn_restore)

        btn_delete = QPushButton("Удалить")
        btn_delete.setMinimumHeight(32)
        btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_delete.setStyleSheet(
            "QPushButton { background-color: rgba(239, 68, 68, 0.15); "
            "color: #ef4444; padding: 8px 16px; border-radius: 6px; "
            "font-weight: 500; border: 1px solid rgba(239, 68, 68, 0.3); }"
            "QPushButton:hover { background-color: rgba(239, 68, 68, 0.25); }"
        )
        btn_delete.clicked.connect(
            lambda: self.on_delete(self.record["id"])
        )
        btns.addWidget(btn_delete)

        layout.addLayout(btns)


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(32, 32, 32, 32)
        root.setSpacing(15)

        head = QHBoxLayout()

        title = QLabel("Карантин")
        title.setObjectName("pageTitle")
        head.addWidget(title)
        head.addStretch()

        self.count_label = QLabel("0 объектов")
        self.count_label.setStyleSheet(
            "color: #8b949e; font-size: 13px; padding-right: 10px; "
            "background: transparent;"
        )
        head.addWidget(self.count_label)

        root.addLayout(head)

        subtitle = QLabel(
            "Изолированные файлы зашифрованы и не могут навредить системе"
        )
        subtitle.setObjectName("pageSubtitle")
        root.addWidget(subtitle)

        self.btn_clear_all = QPushButton("Очистить весь карантин")
        self.btn_clear_all.setMinimumHeight(38)
        self.btn_clear_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear_all.clicked.connect(self._clear_all)
        root.addWidget(self.btn_clear_all)

        self.scroll = SmoothScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet(SCROLL_QSS)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )

        self.scroll_content = QWidget()
        self.scroll_content.setStyleSheet("background-color: transparent;")

        self.items_layout = QVBoxLayout(self.scroll_content)
        self.items_layout.setContentsMargins(0, 5, 10, 5)
        self.items_layout.setSpacing(12)
        self.items_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.scroll.setWidget(self.scroll_content)
        root.addWidget(self.scroll, 1)

    def refresh(self):
        self._clear_layout()
        items = quarantine.list_items()

        self.count_label.setText(f"{len(items)} объектов")

        if not items:
            ph = QFrame()
            ph.setObjectName("qCard")
            ph.setStyleSheet(CARD_QSS)
            ph.setMinimumHeight(240)

            ph_l = QVBoxLayout(ph)
            ph_l.setAlignment(Qt.AlignmentFlag.AlignCenter)
            ph_l.setSpacing(12)

            icon = QLabel("🗄️")
            icon.setStyleSheet("font-size: 56px; color: #30363d;")
            icon.setAlignment(Qt.AlignmentFlag.AlignCenter)

            text = QLabel("Карантин пуст")
            text.setStyleSheet(
                "color: #8b949e; font-size: 16px; background: transparent;"
            )
            text.setAlignment(Qt.AlignmentFlag.AlignCenter)

            hint = QLabel(
                "Опасные файлы будут автоматически "
                "помещены сюда после обнаружения"
            )
            hint.setStyleSheet(
                "color: #6e7681; font-size: 12px; background: transparent;"
            )
            hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
            hint.setWordWrap(True)

            ph_l.addWidget(icon)
            ph_l.addWidget(text)
            ph_l.addWidget(hint)

            self.items_layout.addWidget(ph)
            return

        for record in items:
            widget = QuarantineItem(
                record, self._on_delete, self._on_restore
            )
            self.items_layout.addWidget(widget)

    def _clear_layout(self):
        while self.items_layout.count():
            item = self.items_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()

    def _on_delete(self, item_id: str):
        reply = QMessageBox.question(
            self, "Удаление из карантина",
            "Удалить файл навсегда? Восстановление будет невозможно.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        result = quarantine.delete_item(item_id)
        if result.get("status") == "ok":
            self.refresh()
        else:
            QMessageBox.warning(
                self, "Ошибка", result.get("message", "")
            )

    def _on_restore(self, item_id: str):
        result = quarantine.restore_file(item_id)
        if result.get("status") == "ok":
            QMessageBox.information(
                self, "AegisScan",
                f"Файл восстановлен:\n{result['restored_to']}"
            )
            self.refresh()
        else:
            QMessageBox.warning(
                self, "Ошибка", result.get("message", "")
            )

    def _clear_all(self):
        items = quarantine.list_items()
        if not items:
            QMessageBox.information(
                self, "AegisScan", "Карантин уже пуст."
            )
            return

        reply = QMessageBox.question(
            self, "Очистка карантина",
            f"Удалить все {len(items)} файлов навсегда?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        quarantine.clear_all()
        self.refresh()
        QMessageBox.information(self, "AegisScan", "Карантин очищен.")