# -*- mode: python ; coding: utf-8 -*-
# Primer - PyInstaller spec file
# Build with: pyinstaller Primer.spec

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files

# Get the project root
spec_dir = Path(SPECPATH)
src_dir = spec_dir / 'src'
assets_dir = spec_dir / 'assets'
skills_dir = spec_dir / 'skills'

# Collect mnemonic wordlist data files (english.txt, etc.)
mnemonic_datas = collect_data_files('mnemonic')
# Collect eth_account wordlist data files (used by eth_account.hdaccount.mnemonic)
eth_account_datas = collect_data_files('eth_account')

a = Analysis(
    [str(src_dir / 'app.py')],
    pathex=[str(src_dir)],
    binaries=[],
    datas=[
        (str(assets_dir / 'icon256.ico'), 'assets'),
        (str(assets_dir / 'logo.png'), 'assets'),
        # Include skills folder for agent instructions (SKILL.md served via /agent endpoint)
        (str(skills_dir), 'skills'),
    ] + mnemonic_datas + eth_account_datas,
    hiddenimports=[
        # PyQt6
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        'PyQt6.QtWidgets',
        # Cryptography - core modules for signing
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.utils',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.serialization',
        'cryptography.hazmat.backends.openssl',
        'cryptography.hazmat.backends.openssl.backend',
        'argon2',
        'argon2.low_level',
        # Ethereum - account and signing
        'eth_account',
        'eth_account.hdaccount',
        'eth_account.messages',
        'eth_account.signers',
        'eth_account.signers.local',
        'eth_account._utils.structured_data',
        'eth_account._utils.signing',
        # Ethereum - keys and utilities
        'eth_keys',
        'eth_keys.backends',
        'eth_keys.backends.native',
        'eth_utils',
        'eth_utils.conversions',
        'eth_utils.address',
        'eth_typing',
        'eth_hash',
        'eth_hash.auto',
        'eth_abi',
        'eth_abi.packed',
        # Mnemonic
        'mnemonic',
        # Web3
        'web3',
        'web3.auto',
        'web3.providers',
        'web3.exceptions',
        # Standard library often missed
        'json',
        'hashlib',
        'secrets',
        'uuid',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Primer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(assets_dir / 'icon256.ico'),
)
