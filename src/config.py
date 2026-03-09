"""
config.py — Centralised path and parameter definitions.

All notebooks import this module so that paths and experiment parameters are
defined in a single, auditable location.  Modify ``WORKDIR`` to match your
local installation; every other path is derived automatically.
"""

import os

# ============================================================================
# 1. DIRECTORY LAYOUT
# ============================================================================

WORKDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
"""Root of the TVLA repository (auto-detected from this file's location)."""

BITSTREAM_DIR = os.path.join(WORKDIR, "bitstreams")
RTL_DIR       = os.path.join(WORKDIR, "rtl")
DATA_DIR      = os.path.join(WORKDIR, "data")
DATA_RAW_DIR  = os.path.join(DATA_DIR, "raw")
DATA_COMBINED = os.path.join(DATA_DIR, "combined")
PLOTS_DIR     = os.path.join(WORKDIR, "plots")
SCRIPTS_DIR   = os.path.join(WORKDIR, "scripts")

# Ensure output directories exist
for _d in [PLOTS_DIR, DATA_RAW_DIR, DATA_COMBINED]:
    os.makedirs(_d, exist_ok=True)

# ============================================================================
# 2. FPGA / HARDWARE DEFAULTS
# ============================================================================

DEFINES_FILE = os.path.join(RTL_DIR, "cw305_interface", "cw305_defines_itf.v")
"""Verilog register-map definitions shared across all bitstreams."""

# Bitstream catalogue (design version → file)
BITSTREAMS = {
    "aead_masked":   os.path.join(BITSTREAM_DIR, "cw305_aead_masked.bit"),
    "aead_unmasked": os.path.join(BITSTREAM_DIR, "cw305_aead_unmasked.bit"),
}

# ============================================================================
# 3. TVLA STATISTICAL PARAMETERS
# ============================================================================

THRESHOLD_STD   = 4.5
"""Standard fixed-vs-random TVLA pass/fail threshold (|t| > 4.5 ⟹ leakage)."""

ALPHA_GLOBAL    = 1e-5
"""Family-wise error rate for the Bonferroni (mini-p) correction."""

CHUNK_SIZE      = 5000
"""Number of traces read per I/O chunk during streaming computation."""

# ============================================================================
# 4. ACQUISITION DEFAULTS
# ============================================================================

SAMPLES_PER_CYCLE = 8
"""ADC samples per FPGA clock cycle (depends on adc_src multiplier)."""

DEFAULT_PLATFORM       = "CWLITE"
DEFAULT_TARGET_PLATFORM = "CW305_100t"
DEFAULT_FPGA_CLK_HZ    = 15e6
DEFAULT_ADC_GAIN_DB    = 26

# ============================================================================
# 5. TRACE DATASET NAMING CONVENTION
# ============================================================================

def combined_trace_path(version: str, n_traces_k: int,
                        suffix: str = "", ext: str = ".h5") -> str:
    """Build a canonical filename for a combined trace file.

    Parameters
    ----------
    version : str
        Design version tag, e.g. ``"v5_9"``.
    n_traces_k : str | int
        Trace count label (e.g. ``"1M"``, ``"100k"``).
    suffix : str, optional
        Additional qualifier (e.g. ``"_COMPRESSED"``, ``"_MEAN_CLEANED"``).
    ext : str, optional
        File extension.  Default ``".h5"``.

    Returns
    -------
    str
        Absolute path under ``DATA_COMBINED``.
    """
    fname = f"traces_combined_TVLA_{version}_{n_traces_k}_smpl{suffix}{ext}"
    return os.path.join(DATA_COMBINED, fname)
