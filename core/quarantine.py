"""
Карантин — изоляция опасных файлов с шифрованием.
Файлы перемещаются в защищённую папку и шифруются Fernet.
"""
import os
import sys
import json
import hashlib
import datetime
from cryptography.fernet import Fernet


def _base_dir() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "quarantine")


def _key_path() -> str:
    return os.path.join(_base_dir(), "quarantine.key")


def _index_path() -> str:
    return os.path.join(_base_dir(), "quarantine.json")


def _ensure_dir():
    os.makedirs(_base_dir(), exist_ok=True)


def _get_key() -> bytes:
    _ensure_dir()
    kp = _key_path()
    if not os.path.isfile(kp):
        key = Fernet.generate_key()
        with open(kp, "wb") as f:
            f.write(key)
        return key
    with open(kp, "rb") as f:
        return f.read()


def _get_fernet() -> Fernet:
    return Fernet(_get_key())


def _load_index() -> list:
    _ensure_dir()
    ip = _index_path()
    if not os.path.isfile(ip):
        return []
    try:
        with open(ip, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save_index(items: list):
    _ensure_dir()
    with open(_index_path(), "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def list_items() -> list:
    return _load_index()


def quarantine_file(filepath: str, reason: str = "Обнаружена угроза",
                    source: str = "Manual") -> dict:
    if not os.path.isfile(filepath):
        return {"status": "error", "message": f"Файл не найден: {filepath}"}

    _ensure_dir()

    original_path = os.path.abspath(filepath)
    filename = os.path.basename(filepath)

    try:
        size = os.path.getsize(filepath)
        with open(filepath, "rb") as f:
            raw = f.read()
        sha256 = hashlib.sha256(raw).hexdigest()
    except Exception as e:
        return {"status": "error", "message": f"Ошибка чтения файла: {e}"}

    item_id = datetime.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + sha256[:8]

    try:
        encrypted = _get_fernet().encrypt(raw)
        qpath = os.path.join(_base_dir(), f"{item_id}.qtn")
        with open(qpath, "wb") as f:
            f.write(encrypted)
    except Exception as e:
        return {"status": "error", "message": f"Ошибка шифрования: {e}"}

    try:
        os.remove(filepath)
    except Exception as e:
        try:
            os.remove(qpath)
        except Exception:
            pass
        return {"status": "error", "message": f"Не удалось удалить оригинал: {e}"}

    record = {
        "id": item_id,
        "original_path": original_path,
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "reason": reason,
        "source": source,
        "date": datetime.datetime.now().isoformat(timespec="seconds"),
        "quarantine_file": os.path.basename(qpath),
    }

    items = _load_index()
    items.append(record)
    _save_index(items)

    return {"status": "ok", "record": record}


def restore_file(item_id: str, restore_to: str = None) -> dict:
    items = _load_index()
    record = next((x for x in items if x["id"] == item_id), None)
    if not record:
        return {"status": "error", "message": "Запись не найдена"}

    qpath = os.path.join(_base_dir(), record["quarantine_file"])
    if not os.path.isfile(qpath):
        return {"status": "error", "message": "Файл карантина отсутствует"}

    try:
        with open(qpath, "rb") as f:
            encrypted = f.read()
        decrypted = _get_fernet().decrypt(encrypted)
    except Exception as e:
        return {"status": "error", "message": f"Ошибка расшифровки: {e}"}

    target = restore_to or record["original_path"]
    os.makedirs(os.path.dirname(target), exist_ok=True)

    try:
        with open(target, "wb") as f:
            f.write(decrypted)
    except Exception as e:
        return {"status": "error", "message": f"Ошибка записи: {e}"}

    try:
        os.remove(qpath)
    except Exception:
        pass

    items = [x for x in items if x["id"] != item_id]
    _save_index(items)

    return {"status": "ok", "restored_to": target}


def delete_item(item_id: str) -> dict:
    items = _load_index()
    record = next((x for x in items if x["id"] == item_id), None)
    if not record:
        return {"status": "error", "message": "Запись не найдена"}

    qpath = os.path.join(_base_dir(), record["quarantine_file"])
    try:
        if os.path.isfile(qpath):
            os.remove(qpath)
    except Exception as e:
        return {"status": "error", "message": f"Ошибка удаления: {e}"}

    items = [x for x in items if x["id"] != item_id]
    _save_index(items)
    return {"status": "ok"}


def clear_all() -> dict:
    items = _load_index()
    for rec in items:
        qpath = os.path.join(_base_dir(), rec["quarantine_file"])
        try:
            if os.path.isfile(qpath):
                os.remove(qpath)
        except Exception:
            pass
    _save_index([])
    return {"status": "ok", "removed": len(items)}