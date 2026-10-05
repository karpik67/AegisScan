"""
Управление настройками AegisScan.
Хранит настройки в JSON рядом с корнем проекта (или рядом с .exe).
"""
import os
import sys
import json

DEFAULT_CONFIG = {
    "ai_threshold": 0.70,
    "enable_yara": True,
    "enable_malwarebazaar": True,
    "enable_virustotal": False,
    "enable_ai": True,
    "save_history": True,
    "theme": "dark",
}


def _config_path() -> str:
    """Возвращает путь к config.json."""
    if getattr(sys, "frozen", False):
        # Запущено из .exe — рядом с .exe
        base = os.path.dirname(sys.executable)
    else:
        # Запущено из исходников — корень проекта
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "config.json")


def load() -> dict:
    """Загружает настройки."""
    path = _config_path()
    if not os.path.isfile(path):
        return DEFAULT_CONFIG.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = DEFAULT_CONFIG.copy()
        result.update(data)
        return result
    except Exception as e:
        print(f"[Config] Ошибка загрузки: {e}")
        return DEFAULT_CONFIG.copy()


def save(config: dict) -> bool:
    """Сохраняет настройки."""
    path = _config_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
        print(f"[Config] Сохранено в {path}")
        return True
    except Exception as e:
        print(f"[Config] Ошибка сохранения: {e}")
        return False


def get(key: str):
    return load().get(key, DEFAULT_CONFIG.get(key))


def set_value(key: str, value) -> bool:
    config = load()
    config[key] = value
    return save(config)