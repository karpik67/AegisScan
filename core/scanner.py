"""
Универсальный сканер: YARA → MalwareBazaar → VirusTotal → AI Model.
Учитывает настройки пользователя — какие источники включены.
"""
from core import config
from core import abusech
from core import yara_scanner
from core import ai_model


def scan_file(filepath: str) -> dict:
    """Сканирует файл через включённые источники."""
    errors = []
    settings = config.load()

    # Здесь будем сохранять лучший "чистый" результат,
    # чтобы вернуть его, если ничего угрожающего не найдено
    best_clean = None

    # --- Источник 1: YARA ---
    if settings.get("enable_yara", True):
        yara_result = yara_scanner.scan_file(filepath)
        if yara_result.get("verdict") == "malware":
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
                return mb_result
            best_clean = mb_result  # чисто — запомнили
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
                return ai_result
            elif prob >= threshold * 0.6:
                ai_result["verdict"] = "suspicious"

            # Обогащаем результат AI-вероятностью, если есть
            if best_clean:
                best_clean["ai_probability"] = prob
                best_clean["source"] = f"{best_clean.get('source', 'Scanner')} + AI"
            else:
                best_clean = ai_result
        else:
            errors.append(f"AI: {ai_result.get('message')}")

    # --- Если нашли хоть какой-то "чистый" результат — возвращаем его ---
    if best_clean:
        return best_clean

    # --- Все источники провалились ---
    if not errors:
        errors.append(
            "Все источники выключены в настройках. "
            "Включите хотя бы один на странице «Настройки»."
        )

    return {
        "status": "error",
        "message": "Все источники недоступны:\n" + "\n".join(errors),
    }


def scan_url(url: str) -> dict:
    """Сканирует URL через включённые источники."""
    errors = []
    settings = config.load()

    if settings.get("enable_malwarebazaar", True):
        urlhaus_result = abusech.check_url_urlhaus(url)
        if urlhaus_result.get("status") == "found":
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
        errors.append(
            "Все источники выключены в настройках. "
            "Включите хотя бы один на странице «Настройки»."
        )

    return {
        "status": "error",
        "message": "Все источники недоступны:\n" + "\n".join(errors),
    }