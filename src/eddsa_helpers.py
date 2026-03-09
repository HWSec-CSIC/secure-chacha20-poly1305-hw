"""
EdDSA (Ed25519) hardware-accelerator helper functions.

Provides data-packing, reference vectors, and capture routines
for the CW305 EdDSA high-performance core (``cw305_eddsa_hp_v2``).

Register layout (36 × 64-bit words, SIPO interface)
----------------------------------------------------

==========  ====  =============================================
 Address     #W    Field
==========  ====  =============================================
  0          1     Operation code
  1 –  4     4     Private key   (256 b, LSB-first)
  5 –  8     4     Public key    (256 b, LSB-first)
  9 – 24    16     Message       (1024 b, LSB-first)
 25          1     Message length (bits)
 26 – 33     8     Signature / verification (512 b, LSB-first)
 34 – 35     2     Reserved / padding (written as 0)
==========  ====  =============================================

Copyright 2024-2025 – Anonymous Authors
"""

from __future__ import annotations

import numpy as np

# ── Internal helpers ──────────────────────────────────────────────────

def _to_words_lsb_first(value: int, n_words: int) -> list[int]:
    """Split *value* into *n_words* 64-bit words, LSB at index 0."""
    if n_words <= 0:
        return []
    mask = (1 << (64 * n_words)) - 1
    v = value & mask
    b = v.to_bytes(8 * n_words, byteorder="little", signed=False)
    return [int.from_bytes(b[i * 8 : (i + 1) * 8], "little") for i in range(n_words)]


# ── Public API ────────────────────────────────────────────────────────

def eddsa_pack_and_load(
    target,
    operation: int,
    private: int,
    public: int,
    message: int,
    len_message: int,
    sig_ver: int,
    base_addr: int = 0,
    *,
    verbose: bool = False,
) -> None:
    """
    Pack EdDSA inputs into 36 × 64-bit registers and stream them via ITF.

    Parameters
    ----------
    target : cw.targets.CW305
        Monkey-patched CW305 target (see ``src.itf_driver.patch_target``).
    operation : int
        Operation code (e.g. 0x04 for sign+verify).
    private, public : int
        256-bit private / public keys.
    message : int
        Up to 1024-bit message (left-aligned in the 1024-bit field).
    len_message : int
        Message length in **bits**.
    sig_ver : int
        512-bit signature (for verification) or 0 for signing.
    base_addr : int, optional
        Starting SIPO address (default 0).
    verbose : bool, optional
        Print each register write when *True*.
    """
    regs: list[int] = []

    # 0: operation (1 word)
    regs.append(operation & 0xFFFF_FFFF_FFFF_FFFF)

    # 1-4: private key (4 words)
    regs.extend(_to_words_lsb_first(private, 4))

    # 5-8: public key (4 words)
    regs.extend(_to_words_lsb_first(public, 4))

    # 9-24: message (16 words)
    regs.extend(_to_words_lsb_first(message, 16))

    # 25: message length (1 word)
    regs.append(len_message & 0xFFFF_FFFF_FFFF_FFFF)

    # 26-33: signature verification (8 words)
    regs.extend(_to_words_lsb_first(sig_ver, 8))

    # 34-35: padding
    regs.extend([0, 0])

    # Enable LOAD mode (control = 0b0101: LOAD | IP_RESET)
    target.itf_write_ctrl(0x05)

    for i, val in enumerate(regs):
        target.itf_write_add(base_addr + i)
        target.itf_write_data_in(val)
        if verbose:
            print(f"  reg[{base_addr + i:2d}] = 0x{val:016x}")

    if verbose:
        print(f"EdDSA inputs written to {len(regs)} registers (base {base_addr}).")


# ── Reference test vectors ───────────────────────────────────────────

# Default test vector from the RTL testbench
EDDSA_REF = dict(
    operation=0x04,
    private=int(
        "01dce7bc4bdadd915bfd44842512d7956476155515f4b2f269f592120fb60f46", 16
    ),
    public=int(
        "575D25B579CAD0380AA0CC335924119A9C9B21B7FC74E4E70A4AB26A652CA791", 16
    ),
    message_hex="48656C6C6F2C207468697320697320746865205345206F662051554249502070726F6A656374",
    message_bits=304,
    sig_ver=int(
        "AA1954BD9F75CC7F9FF3D1AFFF7FAFEE0D24F4C57EA9FEAB68B3B4771AF678E4"
        "A511C41EAD09DA415A3B6073ACBADEE714D92A3C732CEF3D053F8BC4497AB40C",
        16,
    ),
)


def _build_message(hex_str: str, bit_len: int, block_size: int = 1024) -> int:
    """Left-align a message inside a *block_size*-bit field."""
    return int(hex_str, 16) << (block_size - bit_len)


def get_reference_vectors() -> dict:
    """Return the default EdDSA reference vectors ready for ``eddsa_pack_and_load``."""
    ref = EDDSA_REF.copy()
    hex_str: str = ref.pop("message_hex")  # type: ignore[assignment]
    bits: int = ref.pop("message_bits")    # type: ignore[assignment]
    ref["message"] = _build_message(hex_str, bits)
    ref["len_message"] = bits
    return ref


# ── Execution helpers ─────────────────────────────────────────────────

def run_eddsa_operation(
    target,
    operation: int,
    private: int,
    public: int,
    message: int,
    len_message: int,
    sig_ver: int,
    clk_div: int = 2,
    *,
    verbose: bool = False,
) -> dict:
    """
    Full reset → load → execute → readback cycle for the EdDSA core.

    Returns
    -------
    dict
        ``valid``, ``error``, ``block_ready`` flags and ``sig_pub`` (raw integer).
    """
    target.itf_clk_div_set(clk_div)

    # Reset sequence
    target.itf_write_ctrl(0x03)      # Reset ITF + IP core
    target.itf_write_add(0)
    target.itf_write_data_in(0x00)
    target.itf_write_ctrl(0x07)      # Un-reset ITF, keep IP reset

    # Load
    eddsa_pack_and_load(
        target, operation, private, public,
        message, len_message, sig_ver,
        verbose=verbose,
    )

    # Start
    target.itf_write_ctrl(0x00)

    # Poll for completion
    while not target.itf_done():
        pass

    # Readback – register 0 is status, registers 1-8 are signature+pubkey
    status = target.itf_read_output_block(start=0, end=1)
    sig_pub = target.itf_read_output_block(start=1, end=9)

    result = dict(
        valid=(status >> 0) & 1,
        error=(status >> 1) & 1,
        block_ready=(status >> 2) & 1,
        sig_pub=sig_pub,
    )
    if verbose:
        print(f"Status: valid={result['valid']}, error={result['error']}, "
              f"block_ready={result['block_ready']}")
        print(f"Sig+Pub: 0x{sig_pub:0128x}")
    return result


def run_eddsa_demo(target, clk_div: int = 2, verbose: bool = True) -> dict:
    """Run the built-in reference vector and return the result dict."""
    ref = get_reference_vectors()
    return run_eddsa_operation(
        target,
        operation=ref["operation"],
        private=ref["private"],
        public=ref["public"],
        message=ref["message"],
        len_message=ref["len_message"],
        sig_ver=ref["sig_ver"],
        clk_div=clk_div,
        verbose=verbose,
    )


# ── ADC helpers (same as aead_helpers but kept here for independence) ─

def to_adc_codes(arr, platform: str = "CWLITE") -> np.ndarray:
    """Convert float trace to integer ADC codes."""
    arr = np.asarray(arr)
    if np.issubdtype(arr.dtype, np.integer):
        return arr.astype(np.int32)
    if platform == "CWHUSKY":
        center, div, max_code = 2**11, 2**12, (2**12) - 1
    else:
        center, div, max_code = 2**9, 2**10, (2**10) - 1
    codes = np.rint(arr * div + center).astype(np.int32)
    return np.clip(codes, 0, max_code)


def get_last_trace_codes(scope, platform: str = "CWLITE") -> np.ndarray:
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
        tr = (
            scope.get_last_trace()
            if hasattr(scope, "get_last_trace")
            else scope.getLastTrace()
        )
        return to_adc_codes(tr, platform)
