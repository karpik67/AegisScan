"""
Локальный YARA-сканер.
Работает и из исходников, и из .exe (PyInstaller).
"""
import os
import sys
import yara


def _resource_path(relative: str) -> str:
    """
    Возвращает абсолютный путь к ресурсу.
    При работе из .exe — берёт из sys._MEIPASS.
    При работе из исходников — относительно этого файла.
    """
    if getattr(sys, "frozen", False):
        base = sys._MEIPASS
        return os.path.join(base, relative)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base, relative)


RULES_DIR = _resource_path("data/rules")
_compiled_rules = None


def _load_rules():
    """Загружает и компилирует все .yar/.yara файлы из data/rules/."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    if not os.path.isdir(RULES_DIR):
        print(f"[YARA] Папка правил не найдена: {RULES_DIR}")
        return None

    rule_files = {}
    for fname in os.listdir(RULES_DIR):
        if fname.endswith((".yar", ".yara")):
            full_path = os.path.join(RULES_DIR, fname)
            namespace = os.path.splitext(fname)[0]
            rule_files[namespace] = full_path

    if not rule_files:
        print(f"[YARA] В папке нет .yar/.yara файлов: {RULES_DIR}")
        return None

    try:
        _compiled_rules = yara.compile(filepaths=rule_files)
    except yara.YaraSyntaxError as e:
        print(f"[YARA] Синтаксическая ошибка в правилах: {e}")
        return None
    except Exception as e:
        print(f"[YARA] Ошибка загрузки правил: {e}")
        return None

    return _compiled_rules


def scan_file(filepath: str) -> dict:
    """Проверяет файл по YARA-правилам."""
    rules = _load_rules()
    if rules is None:
        return {
            "status": "error",
            "message": "YARA-правила не найдены в data/rules/",
        }

    if not os.path.isfile(filepath):
        return {"status": "error", "message": f"Файл не найден: {filepath}"}

    try:
        matches = rules.match(filepath, timeout=30)
    except yara.TimeoutError:
        return {"status": "error", "message": "YARA: таймаут сканирования"}
    except yara.Error as e:
        return {"status": "error", "message": f"YARA ошибка: {e}"}
    except Exception as e:
        return {"status": "error", "message": f"Ошибка: {e}"}

    if not matches:
        return {
            "status": "found",
            "source": "YARA",
            "malicious": 0,
            "total": 1,
            "verdict": "clean",
            "message": "YARA-правила не сработали — файл чист по сигнатурам",
        }

    matched = []
    for m in matches:
        matched.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta),
        })

    return {
        "status": "found",
        "source": "YARA",
        "malicious": len(matched),
        "total": 1,
        "verdict": "malware",
        "matches": matched,
        "message": f"Сработало правил: {len(matched)}",
    }