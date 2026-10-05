"""
Извлекает 18 признаков из PE-файла.
Точно те же признаки, на которых обучалась модель.
"""
import math
import pefile

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

# Признаки в том порядке, в котором их ждёт модель
FEATURE_ORDER = [
    "entropy",
    "num_sections",
    "characteristics",
    "is_dll",
    "entry_point",
    "subsystem",
    "dll_characteristics",
    "section_entropy_max",
    "section_entropy_avg",
    "sections_writable",
    "sections_executable",
    "num_imports",
    "num_dlls",
    "suspicious_apis",
    "num_exports",
    "has_debug",
    "has_tls",
    "has_resources",
]


def _entropy(data: bytes) -> float:
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


def extract_features(filepath: str) -> dict | None:
    """
    Возвращает словарь с 18 признаками.
    None — если файл не является валидным PE.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return None

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except Exception:
        return None

    f = {}
    f["entropy"] = _entropy(data)

    # --- File Header ---
    try:
        f["num_sections"] = pe.FILE_HEADER.NumberOfSections
        f["characteristics"] = pe.FILE_HEADER.Characteristics
        f["is_dll"] = 1 if (pe.FILE_HEADER.Characteristics & 0x2000) else 0
    except Exception:
        f["num_sections"] = 0
        f["characteristics"] = 0
        f["is_dll"] = 0

    # --- Optional Header ---
    try:
        oh = pe.OPTIONAL_HEADER
        f["entry_point"] = oh.AddressOfEntryPoint
        f["subsystem"] = oh.Subsystem
        f["dll_characteristics"] = oh.DllCharacteristics
    except Exception:
        f["entry_point"] = 0
        f["subsystem"] = 0
        f["dll_characteristics"] = 0

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