"""Страница сканера автозагрузки."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMessageBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from core import startup_scanner, process_scanner


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
    finished = pyqtSignal(list)

    def run(self):
        items = startup_scanner.get_all_startup_items()
        self.finished.emit(items)


class ScanWorker(QThread):
    """Проверка exe-файлов через AegisScan."""
    progress = pyqtSignal(int, int, str)
    finished = pyqtSignal(list)

    def __init__(self, items: list):
        super().__init__()
        self.items = items

    def run(self):
        results = []
        total = len(self.items)
        for i, item in enumerate(self.items, 1):
            exe = item.get("exe", "")
            self.progress.emit(i, total, item.get("name", "—"))

            if not exe or not item.get("exists"):
                results.append({**item, "scan_verdict": "skip",
                                "scan_source": "—"})
                continue

            res = process_scanner.scan_process_file(exe)
            verdict = res.get("verdict", res.get("status", "error"))
            source = res.get("source", "—")
            results.append({
                **item,
                "scan_verdict": verdict,
                "scan_source": source,
            })
        self.finished.emit(results)


class StartupPage(QWidget):
    def __init__(self):
        super().__init__()
        self.items = []
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

        title = QLabel("🚀  Автозагрузка")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        head.addWidget(title)
        head.addStretch()

        self.count_label = QLabel("0 записей")
        self.count_label.setStyleSheet(
            "color: #7f849c; font-size: 13px; padding-right: 10px;"
        )
        head.addWidget(self.count_label)

        root.addLayout(head)

        subtitle = QLabel(
            "Программы, запускающиеся при входе в Windows: "
            "реестр, Startup, планировщик задач."
        )
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # Кнопки
        btn_row = QHBoxLayout()

        self.btn_refresh = QPushButton("🔄  Обновить")
        self.btn_refresh.setMinimumHeight(38)
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh)
        btn_row.addWidget(self.btn_refresh)

        self.btn_scan = QPushButton("🔍  Проверить подозрительные")
        self.btn_scan.setMinimumHeight(38)
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.clicked.connect(self.scan_suspicious)
        btn_row.addWidget(self.btn_scan)

        btn_row.addStretch()

        self.btn_remove = QPushButton("🗑  Удалить из автозагрузки")
        self.btn_remove.setMinimumHeight(38)
        self.btn_remove.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_remove.setStyleSheet(
            "QPushButton { background-color: #dc3545; color: white; "
            "padding: 8px 16px; border-radius: 6px; font-weight: 500; }"
            "QPushButton:hover { background-color: #e66771; }"
        )
        self.btn_remove.clicked.connect(self.remove_selected)
        btn_row.addWidget(self.btn_remove)

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
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Название", "Источник", "Команда", "Путь", "Вердикт", "Причина"
        ])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(28)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)

        self.table.setColumnWidth(0, 200)
        self.table.setColumnWidth(1, 150)
        self.table.setColumnWidth(3, 200)
        self.table.setColumnWidth(4, 100)
        self.table.setColumnWidth(5, 260)

        root.addWidget(self.table, 1)

    # ---------- Загрузка ----------
    def refresh(self):
        self.status_label.setText("Загрузка автозагрузки...")
        self.btn_refresh.setEnabled(False)

        self.loader = LoadWorker()
        self.loader.finished.connect(self._on_loaded)
        self.loader.start()

    def _on_loaded(self, items: list):
        self.items = items
        self._populate(items)
        self.btn_refresh.setEnabled(True)

        sus = sum(1 for i in items if i["suspicious"])
        self.count_label.setText(
            f"{len(items)} записей · подозрительных: {sus}"
        )
        self.status_label.setText(
            f"Найдено {len(items)} записей. Подозрительных: {sus}"
        )

    def _populate(self, items: list):
        self.table.setRowCount(len(items))

        for row, it in enumerate(items):
            item_name = QTableWidgetItem(it["name"])
            item_source = QTableWidgetItem(it["source"])
            item_cmd = QTableWidgetItem(it["command"])
            item_exe = QTableWidgetItem(it["exe"] or "—")
            item_verdict = QTableWidgetItem("—")
            item_verdict.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            reason = "; ".join(it.get("reasons", [])) or "—"
            item_reason = QTableWidgetItem(reason)

            if it["suspicious"]:
                red = QColor("#3a1e1e")
                for w in [item_name, item_source, item_cmd,
                          item_exe, item_verdict, item_reason]:
                    w.setBackground(red)
                item_name.setForeground(QColor("#ff6b6b"))

            self.table.setItem(row, 0, item_name)
            self.table.setItem(row, 1, item_source)
            self.table.setItem(row, 2, item_cmd)
            self.table.setItem(row, 3, item_exe)
            self.table.setItem(row, 4, item_verdict)
            self.table.setItem(row, 5, item_reason)

    # ---------- Сканирование ----------
    def scan_suspicious(self):
        sus = [i for i in self.items if i["suspicious"]]
        if not sus:
            QMessageBox.information(
                self, "AegisScan",
                "Подозрительных записей не найдено."
            )
            return

        self._set_busy(True)
        self.scanner_worker = ScanWorker(sus)
        self.scanner_worker.progress.connect(self._on_progress)
        self.scanner_worker.finished.connect(self._on_scan_finished)
        self.scanner_worker.start()

    def _on_progress(self, cur: int, total: int, name: str):
        self.status_label.setText(f"Проверка {cur}/{total}: {name}")

    def _on_scan_finished(self, results: list):
        self._set_busy(False)

        # Обновляем строки таблицы
        name_to_row = {}
        for row in range(self.table.rowCount()):
            it = self.table.item(row, 0)
            if it:
                name_to_row[it.text()] = row

        threats = 0
        for r in results:
            row = name_to_row.get(r["name"])
            if row is None:
                continue

            v = r.get("scan_verdict", "—")
            src = r.get("scan_source", "")

            if v == "malware":
                threats += 1
                text = "🚨 MALWARE"
                col = QColor("#dc3545")
            elif v == "clean":
                text = "✅ Чисто"
                col = QColor("#28a745")
            elif v == "suspicious":
                text = "⚠️ Подозрительный"
                col = QColor("#f9a825")
            elif v == "skip":
                text = "—"
                col = QColor("#7f849c")
            else:
                text = v or "—"
                col = QColor("#7f849c")

            w = self.table.item(row, 4)
            w.setText(text)
            w.setForeground(col)

            rw = self.table.item(row, 5)
            if rw:
                rw.setText(f"{rw.text()} | {src}")

        if threats > 0:
            QMessageBox.warning(
                self, "AegisScan",
                f"Обнаружено {threats} опасных записей в автозагрузке!"
            )
        else:
            QMessageBox.information(
                self, "AegisScan",
                "Угроз среди проверенных записей не найдено."
            )

        self.status_label.setText(f"Проверка завершена. Угроз: {threats}")

    def _set_busy(self, busy: bool):
        self.btn_refresh.setEnabled(not busy)
        self.btn_scan.setEnabled(not busy)
        self.btn_remove.setEnabled(not busy)

    # ---------- Удаление ----------
    def remove_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "AegisScan",
                                    "Выберите запись в таблице.")
            return

        it = self.items[row]
        name = it["name"]
        source = it["source"]
        itype = it["type"]

        reply = QMessageBox.question(
            self, "Удаление из автозагрузки",
            f"Удалить запись «{name}»?\n\nИсточник: {source}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        if itype == "registry":
            res = startup_scanner.remove_registry_item(source, name)
        elif itype == "startup_folder":
            res = startup_scanner.remove_startup_file(it["exe"])
        elif itype == "scheduled_task":
            # Из name убираем TaskPath (формат "<path><name>")
            task_name = name
            # Планировщик в PS принимает полный путь как TaskPath\TaskName
            res = startup_scanner.remove_scheduled_task(task_name)
        else:
            res = {"status": "error", "message": "Неизвестный тип"}

        if res.get("status") == "ok":
            QMessageBox.information(self, "AegisScan",
                                    f"Запись «{name}» удалена.")
            self.refresh()
        else:
            QMessageBox.warning(
                self, "AegisScan",
                f"Не удалось удалить:\n{res.get('message', '')}"
            )