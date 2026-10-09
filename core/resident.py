"""
Резидентная защита — мониторинг файловой системы в реальном времени.
С умной изоляцией: подписанные файлы и файлы > 100 МБ не изолируются.
"""
import os
import time
import queue
from PyQt6.QtCore import QThread, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core import scanner, quarantine, journal


SUSPICIOUS_EXT = {
    ".exe", ".dll", ".msi", ".scr", ".com", ".bat",
    ".cmd", ".ps1", ".vbs", ".js", ".jar", ".zip",
    ".rar", ".7z", ".tar", ".gz",
}

# Максимальный размер для автоматической изоляции (100 МБ)
MAX_AUTO_QUARANTINE_SIZE = 100 * 1024 * 1024


def _get_watch_dirs() -> list:
    home = os.path.expanduser("~")
    dirs = [
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.environ.get("TEMP", ""),
    ]
    return [d for d in dirs if d and os.path.isdir(d)]


class _Handler(FileSystemEventHandler):
    def __init__(self, event_queue: queue.Queue):
        super().__init__()
        self.queue = event_queue

    def _handle(self, path: str):
        if not path:
            return
        ext = os.path.splitext(path)[1].lower()
        if ext in SUSPICIOUS_EXT:
            try:
                self.queue.put_nowait(path)
            except Exception:
                pass

    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._handle(event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)


class ResidentProtector(QThread):
    threat_detected = pyqtSignal(dict)
    scan_result = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self._stop_flag = False
        self._event_queue = queue.Queue()
        self._observer = None
        self._recent = {}
        self._recent_ttl = 60

    def run(self):
        dirs = _get_watch_dirs()
        if not dirs:
            print("[Resident] Нет папок для мониторинга")
            return

        handler = _Handler(self._event_queue)
        self._observer = Observer()
        for d in dirs:
            try:
                self._observer.schedule(handler, d, recursive=False)
                print(f"[Resident] Мониторинг: {d}")
            except Exception as e:
                print(f"[Resident] Не удалось следить за {d}: {e}")

        try:
            self._observer.start()
        except Exception as e:
            print(f"[Resident] Не удалось запустить observer: {e}")
            return

        while not self._stop_flag:
            try:
                path = self._event_queue.get(timeout=0.3)
            except queue.Empty:
                continue

            # Дебаунс — файл может ещё докачиваться
            for _ in range(6):
                if self._stop_flag:
                    break
                time.sleep(0.3)

            if self._stop_flag:
                break

            if not os.path.isfile(path):
                continue

            now = time.time()
            last = self._recent.get(path, 0)
            if now - last < self._recent_ttl:
                continue
            self._recent[path] = now

            self._scan(path)

        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception as e:
                print(f"[Resident] Ошибка остановки observer: {e}")

        print("[Resident] Поток завершён")

    def _scan(self, path: str):
        """Проверяет файл и при необходимости изолирует."""
        try:
            name = os.path.basename(path)
            print(f"[Resident] Проверяю: {name}")

            # Пропускаем слишком большие файлы от автокарантина
            try:
                size = os.path.getsize(path)
            except Exception:
                size = 0

            result = scanner.scan_file(path)
            result["resident_path"] = path
            self.scan_result.emit(result)

            verdict = result.get("verdict", "")
            sig = result.get("signature_status", "unknown")

            # === Решение об автокарантине ===
            if verdict != "malware":
                return

            # 1. Подписанный файл — НЕ изолируем
            if sig == "valid":
                print(f"[Resident] {name} — подписан, пропущен")
                return

            # 2. Слишком большой файл — НЕ изолируем автоматически
            if size > MAX_AUTO_QUARANTINE_SIZE:
                print(f"[Resident] {name} — {size // (1024*1024)} МБ, "
                      f"пропущен (слишком большой)")
                return

            # === Изолируем ===
            qres = quarantine.quarantine_file(
                path,
                reason="Обнаружено резидентной защитой",
                source="Real-time",
            )
            if qres.get("status") == "ok":
                journal.add_event(
                    "quarantine", name, path, "quarantined",
                    "Real-time", "Автоматическая изоляция"
                )
                self.threat_detected.emit({
                    "path": path,
                    "name": name,
                    "result": result,
                    "quarantine_id": qres["record"]["id"],
                })
        except Exception as e:
            print(f"[Resident] Ошибка сканирования: {e}")

    def stop(self):
        """Останавливает поток и ждёт завершения."""
        self._stop_flag = True
        if not self.wait(8000):
            print("[Resident] Принудительное завершение потока")
            self.terminate()
            self.wait(2000)