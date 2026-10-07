"""
Модуль сканирования запущенных процессов.
Использует psutil для получения информации + сигнатуры подозрительности.
"""
import os
import psutil


# Папки, из которых НЕ должны запускаться нормальные программы
SUSPICIOUS_PATHS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp",
    "\\downloads\\",
    "\\public\\",
    "\\windows\\temp",
    "\\programdata\\",
    "\\$recycle.bin",
]

# Подозрительные имена процессов (совпадающие с системными)
SYSTEM_NAMES = [
    "svchost", "lsass", "csrss", "winlogon", "services",
    "smss", "wininit", "taskhost", "dwm",
]

# Расширения, которые не должны быть у процессов
BAD_EXT = [".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1"]

# Легитимные системные пути
SYSTEM_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files",
    "c:\\program files (x86)",
]


def _is_system_path(path: str) -> bool:
    """Проверяет, находится ли файл в системной папке."""
    if not path:
        return False
    low = path.lower()
    return any(low.startswith(p) for p in SYSTEM_PATHS)


def _is_suspicious_path(path: str) -> bool:
    """Проверяет, запущен ли процесс из подозрительной папки."""
    if not path:
        return False
    low = path.lower()
    return any(s in low for s in SUSPICIOUS_PATHS)


def _check_digital_signature(path: str) -> str:
    """
    Проверяет цифровую подпись файла.
    Возвращает: 'signed' | 'unsigned' | 'unknown'
    """
    if not path or not os.path.isfile(path):
        return "unknown"

    try:
        import subprocess
        # Используем PowerShell для проверки подписи
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-AuthenticodeSignature '{path}').Status"
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=0x08000000  # CREATE_NO_WINDOW
        )
        status = result.stdout.strip()
        if status == "Valid":
            return "signed"
        elif status in ("NotSigned", "HashMismatch", "UnknownError"):
            return "unsigned"
        else:
            return "unknown"
    except Exception:
        return "unknown"


def _get_publisher(path: str) -> str:
    """Возвращает издателя файла (CompanyName) через PowerShell."""
    if not path or not os.path.isfile(path):
        return "—"

    try:
        import subprocess
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-Item '{path}').VersionInfo.CompanyName"
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=0x08000000
        )
        pub = result.stdout.strip()
        return pub if pub else "—"
    except Exception:
        return "—"


def get_processes() -> list:
    """
    Возвращает список всех процессов с информацией.
    Каждый — словарь:
        pid, name, exe, username, cpu, ram_mb, publisher,
        signature, suspicious (bool), reasons (list)
    """
    processes = []

    for proc in psutil.process_iter([
        "pid", "name", "exe", "username",
        "cpu_percent", "memory_info",
    ]):
        try:
            info = proc.info
            pid = info["pid"]
            name = info["name"] or "—"
            exe = info["exe"] or ""
            username = info["username"] or "—"

            # RAM в МБ
            mem = info.get("memory_info")
            ram_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0.0

            # CPU
            try:
                cpu = proc.cpu_percent(interval=0)
            except Exception:
                cpu = 0.0

            # Анализ подозрительности
            reasons = []

            if exe:
                low_exe = exe.lower()
                base_name = os.path.basename(low_exe)
                name_no_ext = os.path.splitext(base_name)[0]

                # 1. Запущен из подозрительной папки
                if _is_suspicious_path(exe):
                    reasons.append("Запущен из временной папки")

                # 2. Подозрительное расширение
                ext = os.path.splitext(low_exe)[1]
                if ext in BAD_EXT:
                    reasons.append(f"Подозрительное расширение ({ext})")

                # 3. Имитация системного процесса
                if name_no_ext in SYSTEM_NAMES and not _is_system_path(exe):
                    reasons.append("Имитация системного процесса")

                # 4. Не в системной папке + имя как у системного
                if name_no_ext in SYSTEM_NAMES and _is_suspicious_path(exe):
                    reasons.append("Системное имя вне System32")
            else:
                # Нет пути к exe — подозрительно
                if name != "—" and pid > 4:
                    reasons.append("Не удалось получить путь к файлу")

            suspicious = len(reasons) > 0

            processes.append({
                "pid": pid,
                "name": name,
                "exe": exe or "—",
                "username": username,
                "cpu": round(cpu, 1),
                "ram_mb": ram_mb,
                "publisher": "—",   # заполним отдельно, если понадобится
                "signature": "unknown",
                "suspicious": suspicious,
                "reasons": reasons,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception:
            continue

    # Сортировка: подозрительные вверху, потом по RAM
    processes.sort(key=lambda p: (not p["suspicious"], -p["ram_mb"]))
    return processes


def get_suspicious() -> list:
    """Возвращает только подозрительные процессы."""
    return [p for p in get_processes() if p["suspicious"]]


def kill_process(pid: int) -> dict:
    """Завершает процесс по PID."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except psutil.TimeoutExpired:
            proc.kill()
        return {"status": "ok"}
    except psutil.NoSuchProcess:
        return {"status": "error", "message": "Процесс уже завершён"}
    except psutil.AccessDenied:
        return {"status": "error", "message": "Нет прав. Запустите от имени администратора"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def scan_process_file(exe_path: str) -> dict:
    """
    Проверяет exe-файл процесса через основной сканер AegisScan.
    Импорт scanner — внутри функции, чтобы избежать циклической зависимости.
    """
    if not exe_path or not os.path.isfile(exe_path):
        return {"status": "error", "message": "Файл недоступен"}

    try:
        from core import scanner
        return scanner.scan_file(exe_path)
    except Exception as e:
        return {"status": "error", "message": str(e)}