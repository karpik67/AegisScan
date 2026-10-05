"""Страница ИИ-помощника — чат с DeepSeek."""
import html
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QLineEdit, QPushButton
)
from PyQt6.QtCore import QThread, pyqtSignal
from core import ai_chat


class ChatWorker(QThread):
    """Отправляет запрос в DeepSeek в отдельном потоке."""
    finished = pyqtSignal(dict)

    def __init__(self, messages: list):
        super().__init__()
        self.messages = messages

    def run(self):
        result = ai_chat.chat(self.messages)
        self.finished.emit(result)


class ChatPage(QWidget):
    """Страница чата с ИИ-помощником."""

    def __init__(self):
        super().__init__()
        self.history = []  # [{"role": "user"/"assistant", "content": "..."}]
        self.worker = None
        self.waiting = False
        self._build_ui()
        self._render_history()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(12)

        title = QLabel("🤖  ИИ-помощник")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4; padding-bottom: 5px;"
        )
        layout.addWidget(title)

        subtitle = QLabel(
            "Задайте вопрос о работе AegisScan, кибербезопасности или просто поболтайте."
        )
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px; padding-bottom: 5px;")
        layout.addWidget(subtitle)

        self.history_view = QTextEdit()
        self.history_view.setObjectName("chatHistory")
        self.history_view.setReadOnly(True)
        layout.addWidget(self.history_view, 1)

        input_layout = QHBoxLayout()
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Введите сообщение...")
        self.input_field.setMinimumHeight(40)
        self.input_field.returnPressed.connect(self.send_message)

        self.btn_send = QPushButton("Отправить")
        self.btn_send.setObjectName("sendButton")
        self.btn_send.setMinimumHeight(40)
        self.btn_send.clicked.connect(self.send_message)

        input_layout.addWidget(self.input_field, 1)
        input_layout.addWidget(self.btn_send)
        layout.addLayout(input_layout)

        # Приветствие
        if ai_chat.is_available():
            self.history.append({
                "role": "assistant",
                "content": (
                    "Привет! Я ИИ-помощник AegisScan. "
                    "Задайте вопрос о работе антивируса, кибербезопасности, "
                    "или просто расскажите, чем занимаетесь. 🤖"
                )
            })
        else:
            self.history.append({
                "role": "assistant",
                "content": (
                    "⚠️ DEEPSEEK_API_KEY не задан в .env. "
                    "Чат недоступен. Добавьте ключ и перезапустите приложение."
                )
            })

    def send_message(self):
        text = self.input_field.text().strip()
        if not text or self.waiting:
            return

        self.input_field.clear()
        self.history.append({"role": "user", "content": text})
        self.waiting = True
        self._set_busy(True)
        self._render_history()  # показать вопрос пользователя
        self._append_status("⏳ ИИ думает...")

        self.worker = ChatWorker(self.history)
        self.worker.finished.connect(self._on_reply)
        self.worker.start()

    def _on_reply(self, result: dict):
        self.waiting = False
        self._set_busy(False)

        if result.get("status") == "ok":
            reply = result["reply"]
            self.history.append({"role": "assistant", "content": reply})
        else:
            error = result.get("message", "Неизвестная ошибка")
            self.history.append({
                "role": "assistant",
                "content": f"❌ Ошибка: {error}"
            })

        self._render_history()

    def _set_busy(self, busy: bool):
        self.btn_send.setEnabled(not busy)
        self.input_field.setEnabled(not busy)
        if busy:
            self.input_field.setPlaceholderText("Подождите ответа...")
        else:
            self.input_field.setPlaceholderText("Введите сообщение...")

    def _append_status(self, status: str):
        """Добавляет статус в конец истории (без сохранения)."""
        safe = html.escape(status)
        self.history_view.append(
            f'<div style="color: #7f849c; font-style: italic; margin-top: 8px;">{safe}</div>'
        )

    def _render_history(self):
        """Полностью перерисовывает историю чата."""
        parts = []
        for msg in self.history:
            if msg["role"] == "user":
                prefix = '<span style="color: #89b4fa; font-weight: bold;">Вы:</span>'
                color = "#cdd6f4"
            else:
                prefix = '<span style="color: #a6e3a1; font-weight: bold;">ИИ:</span>'
                color = "#cdd6f4"

            # Правильный порядок: сначала escape, потом замена \n на <br>
            safe = html.escape(msg["content"]).replace("\n", "<br>")

            parts.append(
                f'<div style="margin-top: 12px;">{prefix}</div>'
                f'<div style="color: {color}; margin-left: 12px; '
                f'margin-top: 4px;">{safe}</div>'
            )

        self.history_view.setHtml("".join(parts))

        # Прокрутить вниз
        scrollbar = self.history_view.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())