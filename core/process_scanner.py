"""
Модуль сканирования запущенных процессов.
Использует psutil + сигнатуры + проверку подписи + двойное подтверждение.
"""
import os
import subprocess
import psutil


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

SYSTEM_NAMES = [
    "svchost", "lsass", "csrss", "winlogon", "services",
    "smss", "wininit", "taskhost", "dwm",
]

BAD_EXT = [".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1"]

SYSTEM_PATHS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files",
    "c:\\program files (x86)",
]


def _is_system_path(path: str) -> bool:
    if not path:
        return False
    low = path.lower()
    return any(low.startswith(p) for p in SYSTEM_PATHS)


def _is_suspicious_path(path: str) -> bool:
    if not path:
        return False
    low = path.lower()
    return any(s in low for s in SUSPICIOUS_PATHS)


def check_signature(path: str) -> str:
    """Проверка цифровой подписи файла."""
    if not path or not os.path.isfile(path):
        return "unknown"

    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-AuthenticodeSignature '{path}').Status"
        ]
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=5,
            creationflags=0x08000000,
        )
        status = r.stdout.strip()
        if status == "Valid":
            return "valid"
        if status in ("NotSigned", "HashMismatch", "UnknownError"):
            return "unsigned"
        return "unknown"
    except Exception:
        return "unknown"


def get_processes() -> list:
    """Возвращает список всех процессов с информацией."""
    processes = []

    for proc in psutil.process_iter([
        "pid", "name", "exe", "username", "cpu_percent", "memory_info",
    ]):
        try:
            info = proc.info
            pid = info["pid"]
            name = info["name"] or "—"
            exe = info["exe"] or ""
            username = info["username"] or "—"

            mem = info.get("memory_info")
            ram_mb = round(mem.rss / (1024 * 1024), 1) if mem else 0.0

            try:
                cpu = proc.cpu_percent(interval=0)
            except Exception:
                cpu = 0.0

            reasons = []

            if exe:
                low_exe = exe.lower()
                base_name = os.path.basename(low_exe)
                name_no_ext = os.path.splitext(base_name)[0]

                if _is_suspicious_path(exe):
                    reasons.append("Запущен из временной папки")

                ext = os.path.splitext(low_exe)[1]
                if ext in BAD_EXT:
                    reasons.append(f"Подозрительное расширение ({ext})")

                if name_no_ext in SYSTEM_NAMES and not _is_system_path(exe):
                    reasons.append("Имитация системного процесса")

                if name_no_ext in SYSTEM_NAMES and _is_suspicious_path(exe):
                    reasons.append("Системное имя вне System32")
            else:
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
                "signature": "unknown",
                "suspicious": suspicious,
                "reasons": reasons,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied,
                psutil.ZombieProcess):
            continue
        except Exception:
            continue

    processes.sort(key=lambda p: (not p["suspicious"], -p["ram_mb"]))
    return processes


def get_suspicious() -> list:
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
        return {"status": "error",
                "message": "Нет прав. Запустите от имени администратора"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def scan_process_file(exe_path: str) -> dict:
    """
    Проверяет exe-файл процесса через основной сканер AegisScan.
    Двойная защита от ложных срабатываний:
    1. Если подпись валидна — MALWARE → suspicious
    2. Если подписи нет, но и MalwareBazaar не подтверждает — MALWARE → suspicious
    """
    if not exe_path or not os.path.isfile(exe_path):
        return {"status": "error", "message": "Файл недоступен"}

    try:
        from core import scanner
        result = scanner.scan_file(exe_path)

        # Проверяем только случаи, когда вердикт = malware
        if result.get("verdict") == "malware":
            sig = check_signature(exe_path)
            result["signature_status"] = sig

            # Проверка 1: подпись валидна
            if sig == "valid":
                result["verdict"] = "suspicious"
                result["malicious"] = 0
                source = result.get("source", "")
                result["source"] = f"{source} [подпись OK]"
                result["message"] = "Подписанный файл — понижен до подозрительного"
                return result

            # Проверка 2: MalwareBazaar не подтверждает malware
            source = result.get("source", "")
            if "MalwareBazaar" not in source:
                # Значит MALWARE пришёл от ИИ или YARA.
                # Проверим MB явно.
                try:
                    from core import abusech
                    mb = abusech.check_malwarebazaar(exe_path)
                    if (mb.get("status") == "found"
                            and mb.get("verdict") == "clean"):
                        # MB говорит чисто → понижаем
                        result["verdict"] = "suspicious"
                        result["malicious"] = 0
                        result["source"] = f"{source} [MB: чисто]"
                        result["message"] = (
                            "ИИ подозревает malware, но MalwareBazaar "
                            "не подтверждает — понижен до подозрительного"
                        )
                        return result
                except Exception:
                    pass

        else:
            result["signature_status"] = check_signature(exe_path)

        return result
    except Exception as e:
        return {"status": "error", "message": str(e)}