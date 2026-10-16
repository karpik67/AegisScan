"""Страница сканера сетевых соединений."""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView,
    QPushButton, QMessageBox, QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor

from core import network_scanner


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

    def __init__(self, only_established: bool):
        super().__init__()
        self.only_established = only_established

    def run(self):
        conns = network_scanner.get_connections(
            only_established=self.only_established
        )
        self.finished.emit(conns)


class CountryWorker(QThread):
    progress = pyqtSignal(int, int)
    finished = pyqtSignal(list)

    def __init__(self, connections: list):
        super().__init__()
        self.connections = connections

    def run(self):
        result = network_scanner.enrich_with_countries(
            self.connections,
            progress_callback=lambda cur, total:
                self.progress.emit(cur, total)
        )
        self.finished.emit(result)


class NetworkPage(QWidget):
    def __init__(self):
        super().__init__()
        self.connections = []
        self.loader = None
        self.country_worker = None
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        # Заголовок
        head = QHBoxLayout()

        title = QLabel("🌐  Сеть")
        title.setStyleSheet(
            "font-size: 22px; font-weight: bold; color: #cdd6f4;"
        )
        head.addWidget(title)
        head.addStretch()

        self.count_label = QLabel("0 соединений")
        self.count_label.setStyleSheet(
            "color: #7f849c; font-size: 13px; padding-right: 10px;"
        )
        head.addWidget(self.count_label)

        root.addLayout(head)

        subtitle = QLabel(
            "Активные сетевые соединения. Подозрительные — сверху."
        )
        subtitle.setStyleSheet("color: #7f849c; font-size: 12px;")
        root.addWidget(subtitle)

        # Кнопки
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.btn_refresh = QPushButton("🔄  Обновить")
        self.btn_refresh.setMinimumHeight(34)
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.clicked.connect(self.refresh)
        btn_row.addWidget(self.btn_refresh)

        self.btn_countries = QPushButton("🌍  Страны")
        self.btn_countries.setMinimumHeight(34)
        self.btn_countries.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_countries.clicked.connect(self.load_countries)
        btn_row.addWidget(self.btn_countries)

        self.cb_all = QCheckBox("Все соединения")
        self.cb_all.setStyleSheet("color: #cdd6f4; padding-left: 8px;")
        self.cb_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cb_all.toggled.connect(self.refresh)
        btn_row.addWidget(self.cb_all)

        btn_row.addStretch()

        self.btn_kill = QPushButton("🛑  Завершить")
        self.btn_kill.setMinimumHeight(34)
        self.btn_kill.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_kill.setStyleSheet(
            "QPushButton { background-color: #dc3545; color: white; "
            "padding: 6px 14px; border-radius: 6px; font-weight: 500; }"
            "QPushButton:hover { background-color: #e66771; }"
        )
        self.btn_kill.clicked.connect(self.kill_selected)
        btn_row.addWidget(self.btn_kill)

        root.addLayout(btn_row)

        # Статус
        self.status_label = QLabel("")
        self.status_label.setStyleSheet(
            "color: #89b4fa; font-size: 12px; padding: 2px 0;"
        )
        root.addWidget(self.status_label)

        # Таблица
        self.table = QTableWidget()
        self.table.setStyleSheet(TABLE_QSS)
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Процесс", "PID", "Удалённый адрес",
            "Страна", "Статус", "Тип", "Причина"
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
        self.table.verticalHeader().setDefaultSectionSize(26)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self.table.setColumnWidth(0, 160)
        self.table.setColumnWidth(1, 60)
        self.table.setColumnWidth(2, 170)
        self.table.setColumnWidth(3, 140)
        self.table.setColumnWidth(4, 90)
        self.table.setColumnWidth(5, 55)

        root.addWidget(self.table, 1)

    def refresh(self):
        self.status_label.setText("Загрузка соединений...")
        self.btn_refresh.setEnabled(False)

        only_est = not self.cb_all.isChecked()
        self.loader = LoadWorker(only_est)
        self.loader.finished.connect(self._on_loaded)
        self.loader.start()

    def _on_loaded(self, conns: list):
        self.connections = conns
        self._populate(conns)
        self.btn_refresh.setEnabled(True)

        sus = sum(1 for c in conns if c["suspicious"])
        self.count_label.setText(
            f"{len(conns)} соединений · подозрительных: {sus}"
        )
        self.status_label.setText(
            f"Соединений: {len(conns)}. Подозрительных: {sus}"
        )

    def _populate(self, conns: list):
        self.table.setRowCount(len(conns))

        for row, c in enumerate(conns):
            item_proc = QTableWidgetItem(c["process"])
            item_pid = QTableWidgetItem(str(c["pid"]))
            item_pid.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_remote = QTableWidgetItem(c["remote"])
            item_country = QTableWidgetItem(c.get("country", "—"))
            item_status = QTableWidgetItem(c["status"])
            item_status.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item_type = QTableWidgetItem(c["type"])
            item_type.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            reason = "; ".join(c.get("reasons", [])) or "—"
            item_reason = QTableWidgetItem(reason)

            # Локальные — серым цветом
            if c.get("is_local", False) and not c["suspicious"]:
                gray = QColor("#7f849c")
                for w in [item_proc, item_pid, item_remote, item_country,
                          item_status, item_type, item_reason]:
                    w.setForeground(gray)

            if c["suspicious"]:
                red = QColor("#3a1e1e")
                for w in [item_proc, item_pid, item_remote, item_country,
                          item_status, item_type, item_reason]:
                    w.setBackground(red)
                item_proc.setForeground(QColor("#ff6b6b"))

            self.table.setItem(row, 0, item_proc)
            self.table.setItem(row, 1, item_pid)
            self.table.setItem(row, 2, item_remote)
            self.table.setItem(row, 3, item_country)
            self.table.setItem(row, 4, item_status)
            self.table.setItem(row, 5, item_type)
            self.table.setItem(row, 6, item_reason)

    def load_countries(self):
        if not self.connections:
            QMessageBox.information(self, "AegisScan", "Список пуст.")
            return

        self.btn_countries.setEnabled(False)
        self.status_label.setText("Определение стран...")

        self.country_worker = CountryWorker(self.connections)
        self.country_worker.progress.connect(self._on_country_progress)
        self.country_worker.finished.connect(self._on_countries_loaded)
        self.country_worker.start()

    def _on_country_progress(self, cur: int, total: int):
        self.status_label.setText(f"Определение стран: {cur}/{total}")

    def _on_countries_loaded(self, conns: list):
        self.connections = conns
        self._populate(conns)
        self.btn_countries.setEnabled(True)
        self.status_label.setText("Страны определены.")

    def kill_selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "AegisScan",
                                    "Выберите соединение в таблице.")
            return

        pid_item = self.table.item(row, 1)
        proc_item = self.table.item(row, 0)
        if not pid_item:
            return

        try:
            pid = int(pid_item.text())
        except Exception:
            return

        name = proc_item.text() if proc_item else "?"

        if pid == 0:
            QMessageBox.warning(self, "AegisScan",
                                "У этого соединения нет PID.")
            return

        reply = QMessageBox.question(
            self, "Завершение процесса",
            f"Завершить процесс «{name}» (PID {pid})?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        res = network_scanner.kill_process(pid)
        if res.get("status") == "ok":
            QMessageBox.information(self, "AegisScan",
                                    f"Процесс {name} завершён.")
            self.refresh()
        else:
            QMessageBox.warning(
                self, "AegisScan",
                f"Не удалось завершить:\n{res.get('message', '')}"
            )