"""
Собирает датасет PE-файлов:
- malware из MalwareBazaar (скачиваются как zip, распаковываются в памяти)
- чистые файлы из C:\\Windows\\System32

Извлекает ~30 статических признаков через pefile.
Сохраняет в data/dataset.csv
"""
import os
import io
import csv
import math
import random
import glob
import time
import pyzipper
import requests
import pefile
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

load_dotenv()

AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY")
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(DATA_DIR, "dataset.csv")

MALWARE_COUNT = 100
CLEAN_COUNT = 100
MAX_FILE_SIZE = 30 * 1024 * 1024  # 30 МБ

SUSPICIOUS_APIS = {
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "SetWindowsHookEx", "GetAsyncKeyState", "WinExec",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW", "InternetReadFile",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "VirtualProtect", "CryptEncrypt", "CryptDecrypt",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
}


def make_session():
    """Создаёт requests.Session с повторными попытками при таймаутах."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def entropy(data: bytes) -> float:
    """Считает энтропию Шеннона для блока данных."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    length = len(data)
    for c in counts:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return ent


def extract_features(data: bytes) -> dict | None:
    """Извлекает ~30 признаков из PE-файла. Возвращает None, если не PE."""
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except Exception:
        return None

    f = {}
    f["file_size"] = len(data)
    f["entropy"] = entropy(data)

    # --- File Header ---
    try:
        f["timestamp"] = pe.FILE_HEADER.TimeDateStamp
        f["num_sections"] = pe.FILE_HEADER.NumberOfSections
        f["characteristics"] = pe.FILE_HEADER.Characteristics
        f["is_dll"] = 1 if (pe.FILE_HEADER.Characteristics & 0x2000) else 0
    except Exception:
        f["timestamp"] = 0
        f["num_sections"] = 0
        f["characteristics"] = 0
        f["is_dll"] = 0

    # --- Optional Header ---
    try:
        oh = pe.OPTIONAL_HEADER
        f["entry_point"] = oh.AddressOfEntryPoint
        f["image_base"] = oh.ImageBase
        f["subsystem"] = oh.Subsystem
        f["dll_characteristics"] = oh.DllCharacteristics
        f["size_of_code"] = oh.SizeOfCode
        f["size_of_image"] = oh.SizeOfImage
        f["size_of_headers"] = oh.SizeOfHeaders
        f["checksum"] = oh.CheckSum
    except Exception:
        f["entry_point"] = 0
        f["image_base"] = 0
        f["subsystem"] = 0
        f["dll_characteristics"] = 0
        f["size_of_code"] = 0
        f["size_of_image"] = 0
        f["size_of_headers"] = 0
        f["checksum"] = 0

    # --- Секции ---
    try:
        sec_entropies = []
        writable = 0
        executable = 0
        for s in pe.sections:
            sec_entropies.append(s.get_entropy())
            if s.Characteristics & 0x80000000:
                writable += 1
            if s.Characteristics & 0x20000000:
                executable += 1
        f["section_entropy_max"] = max(sec_entropies) if sec_entropies else 0.0
        f["section_entropy_avg"] = (
            sum(sec_entropies) / len(sec_entropies) if sec_entropies else 0.0
        )
        f["sections_writable"] = writable
        f["sections_executable"] = executable
    except Exception:
        f["section_entropy_max"] = 0.0
        f["section_entropy_avg"] = 0.0
        f["sections_writable"] = 0
        f["sections_executable"] = 0

    # --- Импорты ---
    num_imports = 0
    num_dlls = 0
    suspicious_count = 0
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            num_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    num_imports += 1
                    if imp.name:
                        try:
                            name = imp.name.decode("utf-8", errors="ignore")
                            if name in SUSPICIOUS_APIS:
                                suspicious_count += 1
                        except Exception:
                            pass
    except Exception:
        pass
    f["num_imports"] = num_imports
    f["num_dlls"] = num_dlls
    f["suspicious_apis"] = suspicious_count

    # --- Экспорты ---
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            f["num_exports"] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        else:
            f["num_exports"] = 0
    except Exception:
        f["num_exports"] = 0

    # --- Доп. директории ---
    f["has_debug"] = 1 if hasattr(pe, "DIRECTORY_ENTRY_DEBUG") else 0
    f["has_tls"] = 1 if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0
    f["has_resources"] = 1 if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else 0

    return f


def download_malware_samples(count: int) -> list[bytes]:
    """Скачивает malware-семплы из MalwareBazaar через pyzipper (AES)."""
    print(f"[*] Скачиваю malware-семплы из MalwareBazaar...")
    session = make_session()
    headers = {"Auth-Key": AUTH_KEY}

    r = session.post(
        "https://mb-api.abuse.ch/api/v1/",
        headers=headers,
        data={"query": "get_recent", "selector": "100"},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json()

    if data.get("query_status") != "ok":
        print(f"[!] Ошибка API: {data.get('query_status')}")
        return []

    samples_info = data.get("data", [])
    print(f"[+] Получено {len(samples_info)} записей о malware")

    samples = []
    for info in samples_info:
        if len(samples) >= count:
            break

        sha256 = info.get("sha256_hash")
        file_type = info.get("file_type", "?")
        signature = info.get("signature") or "unknown"

        if file_type not in ("exe", "dll"):
            continue

        print(f"  [{len(samples)+1}/{count}] {sha256[:16]}... ({file_type}, {signature})")

        try:
            r = session.post(
                "https://mb-api.abuse.ch/api/v1/",
                headers=headers,
                data={"query": "get_file", "sha256_hash": sha256},
                timeout=60,
            )
            if r.status_code != 200 or len(r.content) < 100:
                print("    [-] не удалось скачать")
                continue

            # === КЛЮЧЕВОЕ ИЗМЕНЕНИЕ: используем pyzipper вместо zipfile ===
            with pyzipper.AESZipFile(io.BytesIO(r.content)) as z:
                z.pwd = b"infected"
                names = z.namelist()
                if not names:
                    continue
                raw = z.read(names[0])
                if len(raw) > MAX_FILE_SIZE:
                    print("    [-] файл слишком большой")
                    continue
                samples.append(raw)
        except Exception as e:
            print(f"    [-] ошибка: {e}")
            continue

        time.sleep(0.5)  # небольшая пауза между запросами

    print(f"[+] Скачано malware: {len(samples)}")
    return samples


def collect_clean_files(count: int) -> list[bytes]:
    """Собирает чистые PE-файлы из System32."""
    print(f"[*] Собираю чистые файлы из System32...")

    system32 = os.path.join(os.environ["WINDIR"], "System32")
    all_files = []
    for ext in ("*.exe", "*.dll"):
        all_files.extend(glob.glob(os.path.join(system32, ext)))

    random.shuffle(all_files)

    samples = []
    for fpath in all_files:
        if len(samples) >= count:
            break

        try:
            with open(fpath, "rb") as f:
                raw = f.read()
            if len(raw) > MAX_FILE_SIZE:
                continue
            try:
                pefile.PE(data=raw, fast_load=True)
            except Exception:
                continue
            samples.append(raw)
        except Exception:
            continue

    print(f"[+] Собрано чистых файлов: {len(samples)}")
    return samples


def main():
    if not AUTH_KEY:
        print("[!] ABUSECH_AUTH_KEY не задан в .env")
        return

    malware_samples = download_malware_samples(MALWARE_COUNT)
    clean_samples = collect_clean_files(CLEAN_COUNT)

    print(f"\n[*] Извлекаю признаки...")
    rows = []

    for data in malware_samples:
        feats = extract_features(data)
        if feats:
            feats["label"] = 1
            rows.append(feats)

    for data in clean_samples:
        feats = extract_features(data)
        if feats:
            feats["label"] = 0
            rows.append(feats)

    if not rows:
        print("[!] Нет данных для сохранения")
        return

    fieldnames = list(rows[0].keys())

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    m = sum(1 for r in rows if r["label"] == 1)
    c = sum(1 for r in rows if r["label"] == 0)

    print(f"\n[+] Датасет сохранён: {CSV_PATH}")
    print(f"    Malware: {m}")
    print(f"    Clean:   {c}")
    print(f"    Всего:   {len(rows)}")
    print(f"    Признаков: {len(fieldnames) - 1}")


if __name__ == "__main__":
    main()