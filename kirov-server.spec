# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for kirov-server-emulator.
Build with: pyinstaller kirov-server.spec
"""

from pathlib import Path

block_cipher = None

# Paths
ROOT = Path(SPECPATH)
STATIC_PATH = ROOT / "static"
TEMPLATES_PATH = ROOT / "templates"

# Data files to include in the bundle
datas = [
    (str(STATIC_PATH), "static"),
    (str(TEMPLATES_PATH), "templates"),
]

# Hidden imports for dynamic modules
# These are modules that PyInstaller can't detect automatically
hiddenimports = [
    # FastAPI/Starlette
    "fastapi",
    "fastapi.staticfiles",
    "fastapi.routing",
    "fastapi.responses",
    "fastapi.middleware",
    "starlette",
    "starlette.routing",
    "starlette.staticfiles",
    "starlette.responses",
    "starlette.middleware",
    "starlette.middleware.errors",
    "starlette.middleware.exceptions",
    # Uvicorn
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.loops.asyncio",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "uvicorn.lifespan.off",
    # Pydantic ecosystem
    "pydantic",
    "pydantic.fields",
    "pydantic_core",
    "pydantic_settings",
    "pydantic_settings.sources",
    "pydantic_xml",
    "annotated_types",
    # Database
    "sqlmodel",
    "sqlalchemy",
    "sqlalchemy.dialects.sqlite",
    "sqlalchemy.sql.default_comparator",
    "sqlalchemy.pool",
    "sqlalchemy.orm",
    "sqlalchemy.event",
    # Security
    "bcrypt",
    "bcrypt._bcrypt",
    "passlib",
    "passlib.handlers",
    "passlib.handlers.bcrypt",
    "cryptography",
    "cryptography.hazmat",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.backends",
    # SOAP support
    "fastapi_soap",
    "spyne",
    "spyne.application",
    "spyne.decorator",
    "spyne.model",
    "spyne.model.primitive",
    "spyne.protocol",
    "spyne.protocol.soap",
    "spyne.server",
    "spyne.service",
    "lxml",
    "lxml.etree",
    "lxml._elementpath",
    # HTTP
    "h11",
    "httptools",
    "anyio",
    "anyio._backends",
    "anyio._backends._asyncio",
    "sniffio",
    # Standard library often missed
    "encodings",
    "encodings.idna",
    "asyncio",
    "asyncio.base_events",
    "asyncio.events",
    "asyncio.selector_events",
    "email.mime",
    "email.mime.text",
    "email.mime.multipart",
    # Typing
    "typing_extensions",
]

a = Analysis(
    ["run_server.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary modules to reduce size
        "tkinter",
        "matplotlib",
        "PIL",
        "numpy",
        "pandas",
        "scipy",
        "IPython",
        "jupyter",
        "notebook",
        "pytest",
        "pytest_cov",
        "coverage",
        "mypy",
        "ruff",
    ],
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
    name="kirov-server",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
