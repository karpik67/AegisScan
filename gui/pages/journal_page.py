"""Страница журнала событий."""
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
from PyQt6.QtCore import Qt


class JournalPage(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("📋  Журнал событий")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4; padding-bottom: 10px;"
        )
        layout.addWidget(title)

        placeholder = QLabel("Журнал будет добавлен на следующем шаге...")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setStyleSheet("color: #7f849c; font-size: 14px;")
        layout.addWidget(placeholder)
        layout.addStretch()