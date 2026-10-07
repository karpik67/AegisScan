"""Страница сканера процессов."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QScrollArea, QMessageBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from core import process_scanner


CARD_QSS = """
QFrame#procCard {
    background-color: #24273a;
    border: 1px solid #363a4f;
    border-radius: 12px;
}
"""

SCROLL_QSS = """
QScrollArea { background-color: transparent; border: none; }
QScrollArea > QWidget > QWidget { background-color: transparent; }
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
QHeaderView::section:hover {
    background-color: #313244;
}
"""


class LoadWorker(QThread):
    """Загружает процессы в фоне."""
    finished = pyqtSignal(list)

    def run(self):
        procs = process_scanner.get_processes()
        self.finished.emit(procs)


class ScanWorker(QThread):
    """Проверяет файлы процессов через AegisScan."""
    progress = pyqtSignal(int, int, str)  # current, total, name
    finished = pyqtSignal(list)           # список результатов

    def __init__(self, processes: list):
        super().__init__()
        self.processes = processes

    def run(self):
        results = []
        total = len(self.processes)
        for i, proc in enumerate(self.processes, 1):
            exe = proc.get("exe", "")
            name = proc.get("name", "—")
            self.progress.emit(i, total, name)

            if not exe or exe == "—":
                results.append({**proc, "scan_verdict": "skip",
                                "scan_source": "—"})
                continue

            res = process_scanner.scan_process_file(exe)
            verdict = res.get("verdict", res.get("status", "error"))
            source = res.get("source", "—")
            results.append({
                **proc,
                "scan_verdict": verdict,
                "scan_source": source,
            })
        self.finished.emit(results)


class ProcessesPage(QWidget):
    def __init__(self):
        super().__init__()
        self.processes = []
        self.loader = None
        self.scanner_worker = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 30, 30, 30)
        root.setSpacing(15)

        # Заголовок
        head = QHBoxLayout()

        title = QLabel("⚙️  Процессы")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        head.addWidget(title)
        head.addStretch()

        self.count_label = QLabel("0 процессов")
        self.count_label.setStyleSheet(
            "color: #7f849c; font-size: 13px; padding-right: 10px;"
        )
        head.addWidget(self.count_label)

        root.addLayout(head)

        subtitle = QLabel(
            "Проверка запущенных процессов. Подозрительные — сверху."
        )
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # Панель кнопок
        btn_row = QHBoxLayout()

        self.btn_refresh = QPushButton("🔄  Обновить")
        self.btn_refresh.setMinimumHeight(38)
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh)
        btn_row.addWidget(self.btn_refresh)

        self.btn_scan_suspicious = QPushButton("🔍  Проверить подозрительные")
        self.btn_scan_suspicious.setMinimumHeight(38)
        self.btn_scan_suspicious.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan_suspicious.clicked.connect(self.scan_suspicious)
        btn_row.addWidget(self.btn_scan_suspicious)

        self.btn_scan_all = QPushButton("🔍  Проверить все")
        self.btn_scan_all.setMinimumHeight(38)
        self.btn_scan_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan_all.clicked.connect(self.scan_all)
        btn_row.addWidget(self.btn_scan_all)

        btn_row.addStretch()

        self.btn_kill = QPushButton("🛑  Завершить процесс")
        self.btn_kill.setMinimumHeight(38)
        self.btn_kill.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_kill.setStyleSheet(
            "QPushButton { background-color: #dc3545; color: white; "
            "padding: 8px 16px; border-radius: 6px; font-weight: 500; }"
            "QPushButton:hover { background-color: #e66771; }"
        )
        self.btn_kill.clicked.connect(self.kill_selected)
        btn_row.addWidget(self.btn_kill)

        root.addLayout(btn_row)

        # Статус
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(
            "color: #89b4fa; font-size: 12px; padding: 4px 0;"
        )
        root.addWidget(self.status_label)

        # Таблица
        self.table = QTableWidget()
        self.table.setStyleSheet(TABLE_QSS)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "PID", "Имя", "Путь", "CPU %", "RAM (МБ)", "Вердикт", "Причина"
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)

        self.table.setColumnWidth(0, 70)
        self.table.setColumnWidth(1, 160)
        self.table.setColumnWidth(3, 70)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 100)
        self.table.setColumnWidth(6, 220)

        root.addWidget(self.table, 1)

    # ---------- Загрузка процессов ----------
    def refresh(self):
        self.status_label.setText("Загрузка процессов...")
        self.btn_refresh.setEnabled(False)

        self.loader = LoadWorker()
        self.loader.finished.connect(self._on_loaded)
        self.loader.start()

    def _on_loaded(self, procs: list):
        self.processes = procs
        self._populate_table(procs)
        self.btn_refresh.setEnabled(True)

        suspicious = sum(1 for p in procs if p["suspicious"])
        self.count_label.setText(
            f"{len(procs)} процессов · подозрительных: {suspicious}"
        )
        self.status_label.setText(
            f"Загружено {len(procs)} процессов. Подозрительных: {suspicious}"
        )

    def _populate_table(self, procs: list):
        self.table.setRowCount(len(procs))

        for row, p in enumerate(procs):
            # PID
            item_pid = QTableWidgetItem(str(p["pid"]))
            item_pid.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # Имя
            item_name = QTableWidgetItem(p["name"])

            # Путь
            item_path = QTableWidgetItem(p["exe"])

            # CPU
            item_cpu = QTableWidgetItem(f"{p['cpu']:.1f}")
            item_cpu.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # RAM
            item_ram = QTableWidgetItem(f"{p['ram_mb']:.1f}")
            item_ram.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # Вердикт
            item_verdict = QTableWidgetItem("—")
            item_verdict.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            # Причина
            reason = "; ".join(p["reasons"]) if p["reasons"] else "—"
            item_reason = QTableWidgetItem(reason)

            # Подсветка подозрительных
            if p["suspicious"]:
                red = QColor("#3a1e1e")
                for it in [item_pid, item_name, item_path, item_cpu,
                            item_ram, item_verdict, item_reason]:
                    it.setBackground(red)
                item_name.setForeground(QColor("#ff6b6b"))

            self.table.setItem(row, 0, item_pid)
            self.table.setItem(row, 1, item_name)
            self.table.setItem(row, 2, item_path)
            self.table.setItem(row, 3, item_cpu)
            self.table.setItem(row, 4, item_ram)
            self.table.setItem(row, 5, item_verdict)
            self.table.setItem(row, 6, item_reason)

    # ---------- Сканирование ----------
    def scan_suspicious(self):
        suspicious = [p for p in self.processes if p["suspicious"]]
        if not suspicious:
            QMessageBox.information(
                self, "AegisScan",
                "Подозрительных процессов не найдено."
            )
            return
        self._run_scan(suspicious)

    def scan_all(self):
        if not self.processes:
            QMessageBox.information(self, "AegisScan", "Список пуст.")
            return
        reply = QMessageBox.question(
            self, "AegisScan",
            f"Проверить все {len(self.processes)} процессов?\n"
            f"Это может занять несколько минут.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._run_scan(self.processes)

    def _run_scan(self, procs: list):
        self._set_busy(True)

        self.scanner_worker = ScanWorker(procs)
        self.scanner_worker.progress.connect(self._on_scan_progress)
        self.scanner_worker.finished.connect(self._on_scan_finished)
        self.scanner_worker.start()

    def _on_scan_progress(self, current: int, total: int, name: str):
        self.status_label.setText(
            f"Проверка {current}/{total}: {name}"
        )

    def _on_scan_finished(self, results: list):
        self._set_busy(False)

        # Обновляем таблицу — по PID находим строку
        pid_to_row = {}
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item:
                pid_to_row[int(item.text())] = row

        threats = 0
        for r in results:
            row = pid_to_row.get(r["pid"])
            if row is None:
                continue

            verdict = r.get("scan_verdict", "—")
            source = r.get("scan_source", "—")

            if verdict == "malware":
                threats += 1
                text = f"🚨 MALWARE"
                color = QColor("#dc3545")
            elif verdict == "clean":
                text = f"✅ Чисто"
                color = QColor("#28a745")
            elif verdict == "suspicious":
                text = f"⚠️ Подозрительный"
                color = QColor("#f9a825")
            elif verdict == "skip":
                text = "—"
                color = QColor("#7f849c")
            else:
                text = verdict or "—"
                color = QColor("#7f849c")

            item_verdict = self.table.item(row, 5)
            item_verdict.setText(text)
            item_verdict.setForeground(color)

            item_reason = self.table.item(row, 6)
            current = item_reason.text() if item_reason else ""
            item_reason.setText(f"{current} | {source}")

        if threats > 0:
            QMessageBox.warning(
                self, "AegisScan",
                f"Обнаружено {threats} опасных процессов!"
            )
        else:
            QMessageBox.information(
                self, "AegisScan",
                "Угроз среди проверенных процессов не найдено."
            )

        self.status_label.setText(
            f"Проверка завершена. Угроз: {threats}"
        )

    def _set_busy(self, busy: bool):
        self.btn_refresh.setEnabled(not busy)
        self.btn_scan_suspicious.setEnabled(not busy)
        self.btn_scan_all.setEnabled(not busy)
        self.btn_kill.setEnabled(not busy)

    # ---------- Завершение процесса ----------
    def kill_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(
                self, "AegisScan",
                "Выберите процесс в таблице."
            )
            return

        pid_item = self.table.item(row, 0)
        name_item = self.table.item(row, 1)
        if not pid_item:
            return

        pid = int(pid_item.text())
        name = name_item.text() if name_item else "?"

        reply = QMessageBox.question(
            self, "Завершение процесса",
            f"Завершить процесс «{name}» (PID {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        res = process_scanner.kill_process(pid)
        if res.get("status") == "ok":
            QMessageBox.information(
                self, "AegisScan",
                f"Процесс {name} завершён."
            )
            self.refresh()
        else:
            QMessageBox.warning(
                self, "AegisScan",
                f"Не удалось завершить:\n{res.get('message', '')}"
            )