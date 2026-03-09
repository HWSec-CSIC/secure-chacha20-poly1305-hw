"""
aead_helpers.py — ChaCha20-Poly1305 AEAD data packing and test-vector routines.

This module provides functions to:

1. Pack AEAD inputs (key, nonce, AAD, plaintext) into the 64-bit SIPO
   registers of the CW305 AEAD core.
2. Generate software reference outputs via PyCryptodome for functional
   verification against the hardware implementation.
3. Run single-shot and batch functional tests.

All functions operate on an already monkey-patched ``target`` object
(see :mod:`src.itf_driver`).
"""

from __future__ import annotations

import numpy as np

# ============================================================================
# 1. SIPO REGISTER PACKING
# ============================================================================

def aead_pack_and_load(target, key256: int, nonce96: int,
                       aad128: int, aad_len: int,
                       pt: int, pt_len: int,
                       base_addr: int = 0) -> None:
    """Pack all AEAD inputs into SIPO registers and load them via ITF.

    Register layout (17 × 64-bit words):

    ======  ========================================
    Index   Content
    ======  ========================================
    0       ``{pt_len[31:0], aad_len[31:0]}``
    1       Nonce LSB (bytes 4–11)
    2       Nonce MSB (bytes 0–3, zero-extended)
    3–4     AAD (128 bits, big-endian)
    5–8     Key (256 bits, big-endian)
    9–16    Plaintext (512 bits, big-endian)
    ======  ========================================

    Parameters
    ----------
    target : CW305
        Monkey-patched target instance.
    key256, nonce96, aad128, pt : int
        Cryptographic inputs as big-endian integers.
    aad_len, pt_len : int
        Byte lengths of AAD and plaintext.
    base_addr : int, optional
        Base SIPO address offset.
    """
    pt_bytes    = pt.to_bytes(64, "big")
    aad_bytes   = aad128.to_bytes(16, "big")
    key_bytes   = key256.to_bytes(32, "big")
    nonce_bytes = nonce96.to_bytes(12, "big")

    regs = [0] * 17

    # Length field
    regs[0] = ((pt_len & 0xFFFFFFFF) << 32) | (aad_len & 0xFFFFFFFF)
    # Nonce
    regs[1] = int.from_bytes(nonce_bytes[4:12], "big")
    regs[2] = int.from_bytes(nonce_bytes[0:4], "big") & 0xFFFFFFFF
    # AAD
    regs[3] = int.from_bytes(aad_bytes[8:16], "big")
    regs[4] = int.from_bytes(aad_bytes[0:8], "big")
    # Key (4 words, MSB-first packing)
    for k in range(4):
        regs[5 + k] = int.from_bytes(key_bytes[(3 - k) * 8:(4 - k) * 8], "big")
    # Plaintext (8 words)
    for b in range(8):
        regs[9 + b] = int.from_bytes(pt_bytes[(7 - b) * 8:(8 - b) * 8], "big")

    for i in range(len(regs)):
        target.itf_set_control("STANDBY")
        target.itf_write_add(base_addr + i)
        target.itf_write_data_in(regs[i])
        target.itf_set_control("LOAD")
    target.itf_set_control("STANDBY")


def aead_load_key(target, key256: int, base_addr: int = 0) -> None:
    """Load only the 256-bit key into SIPO registers 5–8.

    Used in the fast-capture loop where nonce / AAD / PT remain constant
    and only the key changes per trace.
    """
    key_bytes = key256.to_bytes(32, "big")
    for k in range(4):
        reg_index = 5 + k
        reg_value = int.from_bytes(key_bytes[(3 - k) * 8:(4 - k) * 8], "big")
        target.itf_set_control("STANDBY")
        target.itf_write_add(base_addr + reg_index)
        target.itf_write_data_in(reg_value)
        target.itf_set_control("LOAD")
    target.itf_set_control("STANDBY")


def aead_load_data(target, nonce96: int, aad128: int, aad_len: int,
                   pt: int, pt_len: int, base_addr: int = 0) -> None:
    """Load nonce, AAD, and plaintext (skip key registers 5–8)."""
    pt_bytes    = pt.to_bytes(64, "big")
    aad_bytes   = aad128.to_bytes(16, "big")
    nonce_bytes = nonce96.to_bytes(12, "big")

    regs = [0] * 17
    regs[0] = ((pt_len & 0xFFFFFFFF) << 32) | (aad_len & 0xFFFFFFFF)
    regs[1] = int.from_bytes(nonce_bytes[4:12], "big")
    regs[2] = int.from_bytes(nonce_bytes[0:4], "big") & 0xFFFFFFFF
    regs[3] = int.from_bytes(aad_bytes[8:16], "big")
    regs[4] = int.from_bytes(aad_bytes[0:8], "big")
    for b in range(8):
        regs[9 + b] = int.from_bytes(pt_bytes[(7 - b) * 8:(8 - b) * 8], "big")

    for i in range(len(regs)):
        if 5 <= i <= 8:
            continue  # skip key registers
        target.itf_set_control("STANDBY")
        target.itf_write_add(base_addr + i)
        target.itf_write_data_in(regs[i])
        target.itf_set_control("LOAD")
    target.itf_set_control("STANDBY")


# ============================================================================
# 2. REFERENCE TEST VECTORS (PyCryptodome)
# ============================================================================

# RFC 8439 test vector defaults
_DEFAULT_KEY   = 0x808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F
_DEFAULT_NONCE = 0x070000004041424344454647
_DEFAULT_AAD   = 0x50515253C0C1C2C3C4C5C6C700000000
_DEFAULT_AAD_LEN = 12
_DEFAULT_PT    = 0x4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f
_DEFAULT_PT_LEN = 64


def reference_chacha20_poly1305(key256: int | None = None) -> tuple[int, int]:
    """Compute ChaCha20-Poly1305 reference output with PyCryptodome.

    Parameters
    ----------
    key256 : int, optional
        256-bit key.  Uses RFC 8439 test vector if ``None``.

    Returns
    -------
    ciphertext : int
        512-bit ciphertext as big-endian integer.
    tag : int
        128-bit Poly1305 tag as big-endian integer.
    """
    from Crypto.Cipher import ChaCha20_Poly1305

    if key256 is None:
        key256 = _DEFAULT_KEY
    key_bytes   = key256.to_bytes(32, "big")
    nonce_bytes = _DEFAULT_NONCE.to_bytes(12, "big")
    aad_bytes   = _DEFAULT_AAD.to_bytes(16, "big")[:_DEFAULT_AAD_LEN]

    cipher = ChaCha20_Poly1305.new(key=key_bytes, nonce=nonce_bytes)
    cipher.update(aad_bytes)
    ct_bytes  = cipher.encrypt(_DEFAULT_PT.to_bytes(64, "big"))
    tag_bytes = cipher.digest()

    return int.from_bytes(ct_bytes, "big"), int.from_bytes(tag_bytes, "big")


# ============================================================================
# 3. HARDWARE EXECUTION WRAPPERS
# ============================================================================

def run_aead_test(target, key256: int | None = None,
                  verbose: bool = True) -> tuple[int, int, int]:
    """Full reset → load → execute → read cycle on the AEAD core.

    Returns
    -------
    ciphertext : int
    tag : int
    busy_cnt : int
        Number of core clock cycles the operation took.
    """
    if key256 is None:
        key256 = _DEFAULT_KEY

    target.itf_set_control("NULL")
    target.itf_set_control("RESET")
    target.itf_set_control("RESET_ITF")
    target.itf_set_control("NULL")
    target.itf_set_encrypt(True)

    aead_pack_and_load(target, key256, _DEFAULT_NONCE, _DEFAULT_AAD,
                       _DEFAULT_AAD_LEN, _DEFAULT_PT, _DEFAULT_PT_LEN)
    target.it_set_next_block("NO_OP")
    target.itf_start_test()

    while not target.itf_done():
        pass

    ct  = target.itf_read_ciphertext()
    tag = target.itf_read_tag()
    cnt = target.itf_busy_cnt()

    if verbose:
        print(f"Hardware CT  : {ct:0128x}")
        print(f"Hardware TAG : {tag:032x}")
        print(f"Busy cycles  : {cnt}")

    return ct, tag, cnt


def run_aead_key_only(target, key256: int | None = None) -> None:
    """Fast-path: reset, load key, set NO_OP, and start (no readback)."""
    if key256 is None:
        key256 = _DEFAULT_KEY
    target.itf_set_control("RESET")
    target.itf_set_control("NULL")
    aead_load_key(target, key256)
    target.it_set_next_block("NO_OP")
    target.itf_start_test()


def preload_constant_data(target) -> None:
    """Load nonce, AAD, PT with default test-vector values (call once)."""
    target.itf_set_control("RESET")
    target.itf_set_control("RESET_ITF")
    target.itf_set_control("NULL")
    target.itf_set_encrypt(True)
    aead_load_data(target, _DEFAULT_NONCE, _DEFAULT_AAD,
                   _DEFAULT_AAD_LEN, _DEFAULT_PT, _DEFAULT_PT_LEN)


# ============================================================================
# 4. ADC HELPER
# ============================================================================

def to_adc_codes(arr, platform: str = "CWLITE") -> np.ndarray:
    """Convert floating-point scope output to integer ADC codes.

    Parameters
    ----------
    arr : array_like
        Raw trace data (float voltages or already integer codes).
    platform : str
        ``"CWLITE"`` / ``"CWPRO"`` (10-bit) or ``"CWHUSKY"`` (12-bit).

    Returns
    -------
    codes : ndarray of int32
    """
    arr = np.asarray(arr)
    if np.issubdtype(arr.dtype, np.integer):
        return arr.astype(np.int32)
    if platform == "CWHUSKY":
        center, div, max_code = 2**11, 2**12, (2**12) - 1
    else:
        center, div, max_code = 2**9, 2**10, (2**10) - 1
    codes = np.rint(arr * div + center).astype(np.int32)
    return np.clip(codes, 0, max_code)


def get_last_trace_codes(scope, platform: str) -> np.ndarray:
    """Retrieve the last captured trace as integer ADC codes."""
    try:
        tr = scope.get_last_trace(as_int=True)
        if tr is None:
            raise ValueError("No trace returned")
        arr = np.asarray(tr)
        if np.issubdtype(arr.dtype, np.integer):
            return arr.astype(np.int32)
        return to_adc_codes(arr, platform)
    except TypeError:
        tr = scope.get_last_trace() if hasattr(scope, "get_last_trace") \
            else scope.getLastTrace()
        return to_adc_codes(tr, platform)
