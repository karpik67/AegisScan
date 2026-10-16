"""Страница сканирования дисков."""
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QFileDialog, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from core import disk_scanner, quarantine, journal


CARD_QSS = """
QFrame#diskCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
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


class ScanWorker(QThread):
    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(dict)

    def __init__(self, folder: str):
        super().__init__()
        self.folder = folder
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        result = disk_scanner.scan_folder(
            self.folder,
            progress_callback=lambda cur, tot, path:
                self.progress.emit(cur, tot, path),
            cancel_check=lambda: self._cancel,
        )
        self.finished.emit(result)


class DiskPage(QWidget):
    def __init__(self):
        super().__init__()
        self.folder = ""
        self.worker = None
        self.results = []
        self._build_ui()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 30, 30, 30)
        root.setSpacing(15)

        title = QLabel("💽  Сканирование диска")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        root.addWidget(title)

        subtitle = QLabel(
            "Полная проверка папки или диска. YARA + ИИ-модель по всем файлам."
        )
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # Карточка выбора папки
        card = QFrame()
        card.setObjectName("diskCard")
        card.setStyleSheet(CARD_QSS)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 18, 20, 18)
        card_layout.setSpacing(12)

        row = QHBoxLayout()
        self.lbl_path = QLabel("Папка не выбрана")
        self.lbl_path.setStyleSheet(
            "color: #cdd6f4; font-size: 13px; font-family: Consolas;"
        )
        self.lbl_path.setWordWrap(True)
        row.addWidget(self.lbl_path, 1)

        btn_folder = QPushButton("📁  Выбрать папку")
        btn_folder.setMinimumHeight(36)
        btn_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_folder.clicked.connect(self.choose_folder)
        row.addWidget(btn_folder)
        card_layout.addLayout(row)

        quick_row = QHBoxLayout()
        quick_row.setSpacing(8)

        for label, path_func in [
            ("🏠  Домашняя папка", lambda: os.path.expanduser("~")),
            ("⬇  Загрузки", lambda: os.path.join(
                os.path.expanduser("~"), "Downloads")),
            ("💻  Рабочий стол", lambda: os.path.join(
                os.path.expanduser("~"), "Desktop")),
            ("📄  Документы", lambda: os.path.join(
                os.path.expanduser("~"), "Documents")),
            ("🖥  Диск C:\\", lambda: "C:\\"),
        ]:
            b = QPushButton(label)
            b.setMinimumHeight(32)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(
                lambda _, f=path_func: self._set_folder(f())
            )
            quick_row.addWidget(b)

        quick_row.addStretch()
        card_layout.addLayout(quick_row)
        root.addWidget(card)

        # Прогресс-бар
        self.progress_frame = QFrame()
        self.progress_frame.setObjectName("diskCard")
        self.progress_frame.setStyleSheet(CARD_QSS)
        self.progress_frame.setVisible(False)

        prog_layout = QVBoxLayout(self.progress_frame)
        prog_layout.setContentsMargins(20, 15, 20, 15)
        prog_layout.setSpacing(10)

        self.lbl_progress = QLabel("Готов к сканированию")
        self.lbl_progress.setStyleSheet("color: #cdd6f4; font-size: 13px;")
        prog_layout.addWidget(self.lbl_progress)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #181825;
                border: none;
                border-radius: 6px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #89b4fa;
                border-radius: 6px;
            }
        """)
        prog_layout.addWidget(self.progress_bar)

        self.lbl_current = QLabel("")
        self.lbl_current.setStyleSheet(
            "color: #7f849c; font-size: 11px; font-family: Consolas;"
        )
        self.lbl_current.setWordWrap(True)
        prog_layout.addWidget(self.lbl_current)

        root.addWidget(self.progress_frame)

        # Кнопки управления
        btn_row = QHBoxLayout()
        btn_row.setSpacing(10)

        self.btn_start = QPushButton("▶  Начать сканирование")
        self.btn_start.setMinimumHeight(42)
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.setStyleSheet(
            "QPushButton { background-color: #89b4fa; color: #1e1e2e; "
            "font-weight: bold; padding: 8px 20px; border-radius: 8px; }"
            "QPushButton:hover { background-color: #b4befe; }"
            "QPushButton:disabled { background-color: #313244; color: #585b70; }"
        )
        self.btn_start.clicked.connect(self.start_scan)
        btn_row.addWidget(self.btn_start)

        self.btn_cancel = QPushButton("🛑  Отмена")
        self.btn_cancel.setMinimumHeight(42)
        self.btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setStyleSheet(
            "QPushButton { background-color: #dc3545; color: white; "
            "font-weight: 500; padding: 8px 20px; border-radius: 8px; }"
            "QPushButton:hover { background-color: #e66771; }"
        )
        self.btn_cancel.clicked.connect(self.cancel_scan)
        btn_row.addWidget(self.btn_cancel)

        btn_row.addStretch()

        self.btn_isolate = QPushButton("🗄  Изолировать все угрозы")
        self.btn_isolate.setMinimumHeight(42)
        self.btn_isolate.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_isolate.setVisible(False)
        self.btn_isolate.setStyleSheet(
            "QPushButton { background-color: #dc3545; color: white; "
            "font-weight: 500; padding: 8px 20px; border-radius: 8px; }"
            "QPushButton:hover { background-color: #e66771; }"
        )
        self.btn_isolate.clicked.connect(self.isolate_all)
        btn_row.addWidget(self.btn_isolate)

        root.addLayout(btn_row)

        self.lbl_status = QLabel("")
        self.lbl_status.setStyleSheet(
            "color: #89b4fa; font-size: 12px;"
        )
        root.addWidget(self.lbl_status)

        # Таблица
        self.table = QTableWidget()
        self.table.setStyleSheet(TABLE_QSS)
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels([
            "Файл", "Путь", "Источник", "Сообщение"
        ])
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)

        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(2, 140)
        self.table.setColumnWidth(3, 250)

        root.addWidget(self.table, 1)

    def _set_folder(self, path: str):
        if not path or not os.path.isdir(path):
            return
        self.folder = path
        self.lbl_path.setText(path)
        self.lbl_status.setText(
            f"Выбрана папка: {os.path.basename(path) or path}"
        )

    def choose_folder(self):
        path = QFileDialog.getExistingDirectory(
            self, "Выберите папку для сканирования",
            os.path.expanduser("~")
        )
        if path:
            self._set_folder(path)

    def start_scan(self):
        if not self.folder:
            QMessageBox.information(
                self, "AegisScan",
                "Сначала выберите папку для сканирования."
            )
            return

        # Ждём, если предыдущий поток ещё работает
        if self.worker is not None and self.worker.isRunning():
            QMessageBox.information(
                self, "AegisScan",
                "Сканирование уже выполняется."
            )
            return

        self.results = []
        self.table.setRowCount(0)
        self.btn_start.setVisible(False)
        self.btn_isolate.setVisible(False)
        self.btn_cancel.setVisible(True)
        self.progress_frame.setVisible(True)
        self.progress_bar.setValue(0)
        self.lbl_progress.setText("Сканирование...")
        self.lbl_status.setText("")

        self.worker = ScanWorker(self.folder)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def cancel_scan(self):
        if self.worker:
            self.worker.cancel()
            self.lbl_progress.setText("Отмена...")

    def _on_progress(self, cur: int, total: int, path: str):
        if total > 0:
            percent = int((cur / total) * 100)
            self.progress_bar.setValue(percent)
            self.lbl_progress.setText(
                f"Проверено {cur} из {total} файлов ({percent}%)"
            )
        if path:
            short = path if len(path) < 80 else "..." + path[-77:]
            self.lbl_current.setText(short)

    def _on_finished(self, result: dict):
        self.btn_start.setVisible(True)
        self.btn_cancel.setVisible(False)

        # Корректно ждём завершения потока перед обнулением
        if self.worker is not None:
            self.worker.wait(2000)
            self.worker = None

        threats = result.get("threats", [])
        self.results = threats

        for t in threats:
            row = self.table.rowCount()
            self.table.insertRow(row)

            item_name = QTableWidgetItem(t["name"])
            item_path = QTableWidgetItem(t["path"])
            item_source = QTableWidgetItem(t["source"])
            item_msg = QTableWidgetItem(t.get("message", ""))

            red = QColor("#3a1e1e")
            for w in [item_name, item_path, item_source, item_msg]:
                w.setBackground(red)
            item_name.setForeground(QColor("#ff6b6b"))

            self.table.setItem(row, 0, item_name)
            self.table.setItem(row, 1, item_path)
            self.table.setItem(row, 2, item_source)
            self.table.setItem(row, 3, item_msg)

        cancelled = result.get("cancelled", False)
        scanned = result.get("scanned", 0)
        total = result.get("total", 0)
        errors = result.get("errors", 0)

        if cancelled:
            self.lbl_progress.setText(
                f"Отменено. Проверено: {scanned} из {total}"
            )
        else:
            self.progress_bar.setValue(100)
            self.lbl_progress.setText(
                f"Сканирование завершено. Проверено: {scanned} из {total}"
            )

        self.lbl_current.setText("")

        if threats:
            self.lbl_status.setText(
                f"🚨 Обнаружено угроз: {len(threats)}. "
                f"Ошибок: {errors}."
            )
            self.btn_isolate.setVisible(True)
        else:
            self.lbl_status.setText(
                f"✅ Угроз не найдено. Ошибок: {errors}."
            )

        try:
            journal.add_event(
                "scan", f"Диск: {result.get('root', '')}", "",
                "malware" if threats else "clean",
                "Disk Scanner",
                f"Проверено {scanned} файлов, угроз: {len(threats)}"
            )
        except Exception:
            pass

    def isolate_all(self):
        if not self.results:
            return

        reply = QMessageBox.question(
            self, "Изоляция угроз",
            f"Изолировать все {len(self.results)} файлов в карантин?\n\n"
            f"Файлы будут зашифрованы и перемещены.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        ok = 0
        fail = 0
        for t in self.results:
            res = quarantine.quarantine_file(
                t["path"],
                reason="Обнаружено при сканировании диска",
                source="Disk Scanner",
            )
            if res.get("status") == "ok":
                ok += 1
                journal.add_event(
                    "quarantine", t["name"], t["path"],
                    "quarantined", "Disk Scanner",
                    "Изолирован после сканирования"
                )
            else:
                fail += 1

        QMessageBox.information(
            self, "AegisScan",
            f"Изолировано: {ok}\nНе удалось: {fail}"
        )

        self.results = []
        self.btn_isolate.setVisible(False)

    def cleanup(self):
        """Останавливает активные потоки перед закрытием приложения."""
        if self.worker is not None and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)
        self.worker = None