"""
Полное сканирование папок и дисков.
Рекурсивный обход + быстрая проверка (YARA + AI) с защитой от ложных срабатываний.
"""
import os
import subprocess


DEFAULT_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".msi",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".doc", ".docx", ".xls", ".xlsx", ".pdf",
    ".apk", ".elf", ".so",
}

EXCLUDE_DIRS = {
    "$recycle.bin", "system volume information",
    "windows", "winsxs", "installer",
    "node_modules", ".git", ".venv", "venv",
    "__pycache__", ".cache",
}

MAX_FILE_SIZE = 200 * 1024 * 1024

# Максимальный размер для вердикта MALWARE без подписи
# Большие файлы (>50 МБ) — обычно установщики, не malware
SUSPICIOUS_SIZE_THRESHOLD = 50 * 1024 * 1024


def _check_signature(path: str) -> str:
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


def collect_files(root_dir: str,
                  extensions: set = None,
                  exclude_dirs: set = None,
                  max_size: int = MAX_FILE_SIZE) -> list:
    """Собирает список файлов для проверки."""
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS
    if exclude_dirs is None:
        exclude_dirs = EXCLUDE_DIRS

    files = []

    try:
        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in exclude_dirs
            ]

            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if extensions and ext not in extensions:
                    continue

                fpath = os.path.join(dirpath, fname)

                try:
                    if os.path.getsize(fpath) > max_size:
                        continue
                except Exception:
                    continue

                files.append(fpath)

                if len(files) >= 20000:
                    return files
    except Exception as e:
        print(f"[Disk] Ошибка обхода: {e}")

    return files


def _scan_file_fast(filepath: str) -> dict:
    """
    Быстрая проверка: YARA + AI с защитой от ложных срабатываний.
    - Подписанный файл → malware понижается до suspicious
    - Большой файл (>50 МБ) без подписи → malware понижается до suspicious
    """
    from core import yara_scanner, ai_model

    # 1. YARA
    yara_result = yara_scanner.scan_file(filepath)
    if yara_result.get("verdict") == "malware":
        return yara_result

    # 2. AI-модель
    ai_result = ai_model.scan_file(filepath)
    if ai_result.get("status") == "found":
        prob = ai_result.get("probability", 0)

        if prob >= 0.70:
            # === Защита от ложных срабатываний ===
            sig = _check_signature(filepath)
            try:
                size = os.path.getsize(filepath)
            except Exception:
                size = 0

            # Подписанный файл — не malware
            if sig == "valid":
                ai_result["verdict"] = "suspicious"
                ai_result["malicious"] = 0
                ai_result["source"] = "AI [подпись OK]"
                ai_result["message"] = (
                    "ИИ подозревает malware, но файл подписан"
                )
                return ai_result

            # Большой файл (>50 МБ) — скорее всего установщик
            if size > SUSPICIOUS_SIZE_THRESHOLD:
                ai_result["verdict"] = "suspicious"
                ai_result["malicious"] = 0
                ai_result["source"] = "AI [большой файл]"
                ai_result["message"] = (
                    f"ИИ подозревает malware, но файл большой "
                    f"({size // (1024*1024)} МБ) — обычно установщик"
                )
                return ai_result

            # Настоящий malware
            ai_result["verdict"] = "malware"
            ai_result["malicious"] = 1
            ai_result["signature_status"] = sig
            return ai_result

        # Обогащаем YARA-результат вероятностью AI
        if yara_result.get("status") == "found":
            yara_result["ai_probability"] = prob
            yara_result["source"] = "YARA + AI"
            return yara_result
        return ai_result

    return yara_result


def scan_folder(root_dir: str,
                progress_callback=None,
                cancel_check=None,
                use_fast_scan: bool = True) -> dict:
    """Сканирует папку."""
    files = collect_files(root_dir)
    total = len(files)

    if progress_callback:
        progress_callback(0, total, "")

    threats = []
    scanned = 0
    errors = 0

    for i, filepath in enumerate(files, 1):
        if cancel_check and cancel_check():
            break

        try:
            if use_fast_scan:
                result = _scan_file_fast(filepath)
            else:
                from core import scanner
                result = scanner.scan_file(filepath)

            scanned += 1

            if result.get("verdict") == "malware":
                threats.append({
                    "path": filepath,
                    "name": os.path.basename(filepath),
                    "verdict": "malware",
                    "source": result.get("source", "—"),
                    "message": result.get("message", ""),
                    "result": result,
                })
        except Exception as e:
            errors += 1
            print(f"[Disk] Ошибка проверки {filepath}: {e}")

        if progress_callback:
            progress_callback(i, total, filepath)

    return {
        "root": root_dir,
        "total": total,
        "scanned": scanned,
        "threats": threats,
        "errors": errors,
        "cancelled": bool(cancel_check and cancel_check()),
    }