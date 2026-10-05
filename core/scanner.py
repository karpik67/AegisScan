"""
Универсальный сканер: YARA → MalwareBazaar → VirusTotal → AI Model.
Пишет результат в журнал.
"""
import os
from core import config
from core import abusech
from core import yara_scanner
from core import ai_model
from core import journal


def _log_event(event_type: str, name: str, path: str,
               verdict: str, source: str, details: str):
    """Пишет в журнал, если это разрешено в настройках."""
    try:
        settings = config.load()
        if settings.get("save_history", True):
            journal.add_event(
                event_type=event_type,
                object_name=name,
                object_path=path,
                verdict=verdict,
                source=source,
                details=details,
            )
    except Exception as e:
        print(f"[Scanner] Journal error: {e}")


def scan_file(filepath: str) -> dict:
    """Сканирует файл. Пишет результат в журнал."""
    errors = []
    settings = config.load()
    best_clean = None

    # --- Источник 1: YARA ---
    if settings.get("enable_yara", True):
        yara_result = yara_scanner.scan_file(filepath)
        if yara_result.get("verdict") == "malware":
            _log_event(
                "scan", os.path.basename(filepath), filepath,
                "malware", yara_result.get("source", "YARA"),
                yara_result.get("message", ""),
            )
            return yara_result
        if yara_result.get("status") == "found":
            best_clean = yara_result
        elif yara_result.get("status") == "error":
            errors.append(f"YARA: {yara_result.get('message')}")

    # --- Источник 2: MalwareBazaar ---
    if settings.get("enable_malwarebazaar", True):
        mb_result = abusech.check_malwarebazaar(filepath)
        if mb_result.get("status") == "found":
            if mb_result.get("verdict") == "malware":
                _log_event(
                    "scan", os.path.basename(filepath), filepath,
                    "malware", mb_result.get("source", "MalwareBazaar"),
                    mb_result.get("message", ""),
                )
                return mb_result
            best_clean = mb_result
        else:
            errors.append(f"MalwareBazaar: {mb_result.get('message')}")

    # --- Источник 3: VirusTotal ---
    if settings.get("enable_virustotal", False):
        try:
            from core import virustotal
            if virustotal.VT_API_KEY:
                vt_result = virustotal.scan_file(filepath)
                if vt_result.get("status") in ("found", "completed"):
                    if vt_result.get("malicious", 0) > 0:
                        _log_event(
                            "scan", os.path.basename(filepath), filepath,
                            "malware", "VirusTotal",
                            f"Обнаружено {vt_result.get('malicious')} движками",
                        )
                        return vt_result
                    best_clean = vt_result
                else:
                    errors.append(f"VirusTotal: {vt_result.get('message')}")
        except Exception as e:
            errors.append(f"VirusTotal недоступен: {e}")

    # --- Источник 4: AI-модель ---
    if settings.get("enable_ai", True):
        ai_result = ai_model.scan_file(filepath)
        if ai_result.get("status") == "found":
            prob = ai_result.get("probability", 0)
            threshold = settings.get("ai_threshold", 0.70)

            if prob >= threshold:
                ai_result["verdict"] = "malware"
                ai_result["malicious"] = 1
                _log_event(
                    "scan", os.path.basename(filepath), filepath,
                    "malware", "AI Model",
                    f"Вероятность malware: {prob * 100:.1f}%",
                )
                return ai_result
            elif prob >= threshold * 0.6:
                ai_result["verdict"] = "suspicious"

            if best_clean:
                best_clean["ai_probability"] = prob
                best_clean["source"] = f"{best_clean.get('source', 'Scanner')} + AI"
            else:
                best_clean = ai_result
        else:
            errors.append(f"AI: {ai_result.get('message')}")

    # --- Результат ---
    if best_clean:
        _log_event(
            "scan", os.path.basename(filepath), filepath,
            "clean", best_clean.get("source", "Scanner"),
            best_clean.get("message", ""),
        )
        return best_clean

    # --- Ошибка ---
    if not errors:
        errors.append("Все источники выключены в настройках.")

    msg = "Все источники недоступны:\n" + "\n".join(errors)
    _log_event(
        "scan", os.path.basename(filepath), filepath,
        "error", "—", msg,
    )
    return {"status": "error", "message": msg}


def scan_url(url: str) -> dict:
    """Сканирует URL. Пишет результат в журнал."""
    errors = []
    settings = config.load()

    if settings.get("enable_malwarebazaar", True):
        urlhaus_result = abusech.check_url_urlhaus(url)
        if urlhaus_result.get("status") == "found":
            verdict = urlhaus_result.get("verdict", "clean")
            _log_event(
                "scan", url, url,
                verdict, urlhaus_result.get("source", "URLhaus"),
                urlhaus_result.get("message", ""),
            )
            return urlhaus_result
        errors.append(f"URLhaus: {urlhaus_result.get('message')}")

    if settings.get("enable_virustotal", False):
        try:
            from core import virustotal
            if virustotal.VT_API_KEY:
                vt_result = virustotal.scan_url(url)
                if vt_result.get("status") in ("found", "completed"):
                    return vt_result
                errors.append(f"VirusTotal: {vt_result.get('message')}")
        except Exception as e:
            errors.append(f"VirusTotal недоступен: {e}")

    if not errors:
        errors.append("Все источники выключены в настройках.")

    msg = "Все источники недоступны:\n" + "\n".join(errors)
    _log_event("scan", url, url, "error", "—", msg)
    return {"status": "error", "message": msg}