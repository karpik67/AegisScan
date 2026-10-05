# -*- mode: python ; coding: utf-8 -*-
"""
Конфигурация PyInstaller для AegisScan.
Запуск: pyinstaller build.spec
Результат: dist/AegisScan.exe
"""
import os

block_cipher = None

# Папки с ресурсами, которые нужно упаковать внутрь .exe
datas = [
    ("data/rules", "data/rules"),
    ("model/lgbm_model.txt", "model"),
]

# Скрытые импорты — PyInstaller иногда не видит модули, которые
# используются динамически
hiddenimports = [
    "lightgbm",
    "sklearn",
    "sklearn.utils._typedefs",
    "sklearn.utils._heap",
    "sklearn.utils._sorting",
    "sklearn.utils._vector_sentinel",
    "scipy",
    "scipy.sparse",
    "scipy.sparse.csgraph",
    "pandas",
    "numpy",
    "pefile",
    "yara",
    "requests",
    "dotenv",
    "cryptography",
]

# Модули, которые не нужны в .exe и только увеличивают размер
excludes = [
    "matplotlib",
    "tkinter",
    "PyQt5",
    "PySide2",
    "PySide6",
    "IPython",
    "jupyter",
    "notebook",
    "pytest",
]


a = Analysis(
    ["main.py"],
    pathex=[os.path.abspath(".")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="AegisScan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,       # ← без чёрного окна консоли
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon="icon.ico",  # ← опционально, если сделаете иконку
)