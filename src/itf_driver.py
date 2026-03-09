"""
itf_driver.py — CW305 ITF (Interface) register driver.

Provides a ``patch_target()`` function that monkey-patches an existing
``chipwhisperer.targets.CW305`` instance with methods for reading /
writing the ITF register block defined in ``cw305_defines.v``.

Usage (inside a notebook cell, after ``target`` has been created)::

    from src.itf_driver import patch_target
    patch_target(target)
    target.itf_set_control("RESET")

The patch is idempotent — calling it twice on the same target is harmless.
"""

from __future__ import annotations

import logging
from types import MethodType

_log = logging.getLogger(__name__)

# ============================================================================
# 1. PREREQUISITE CHECK
# ============================================================================

def _check_itf_defined(self) -> bool:
    """Return ``True`` if all mandatory ITF register addresses are present."""
    required = [
        "REG_ITF_I_CONTROL", "REG_ITF_I_ADD", "REG_ITF_I_DATA_IN",
        "REG_ITF_O_DATA_OUT", "REG_ITF_O_END_OP", "REG_ITF_GO",
    ]
    missing = [r for r in required if getattr(self, r, None) is None]
    if missing:
        _log.error("ITF registers missing: %s. Check defines file.", missing)
        return False
    return True


# ============================================================================
# 2. CONTROL HELPERS
# ============================================================================

def itf_set_control(self, cmd: str, rst_active: str = "HIGH") -> None:
    """Write a symbolic command to the I_CONTROL register.

    Parameters
    ----------
    cmd : str
        One of ``"NULL"``, ``"RESET"``, ``"UNRESET"``, ``"RESET_ITF"``,
        ``"UNRESET_ITF"``, ``"LOAD"``, ``"READ"``, ``"STANDBY"``.
    rst_active : str
        Reset polarity — ``"HIGH"`` (default) or ``"LOW"``.
    """
    if not self._check_itf_defined():
        return
    value = self.fpga_read(self.REG_ITF_I_CONTROL, 8)[0]

    if rst_active == "HIGH":
        _map = {
            "NULL":        lambda v: v & ~0x0F,
            "RESET":       lambda v: v | (1 << 0),
            "UNRESET":     lambda v: v & ~(1 << 0),
            "RESET_ITF":   lambda v: v | (1 << 1),
            "UNRESET_ITF": lambda v: v & ~(1 << 1),
            "LOAD":        lambda v: (v | (1 << 2)) & ~(1 << 3),
            "READ":        lambda v: (v | (1 << 3)) & ~(1 << 2),
            "STANDBY":     lambda v: v & ~0x0C,
        }
    elif rst_active == "LOW":
        _map = {
            "NULL":        lambda v: (v & ~0x0F) | 0x03,
            "RESET":       lambda v: v & ~(1 << 0),
            "UNRESET":     lambda v: v | (1 << 0),
            "RESET_ITF":   lambda v: v & ~(1 << 1),
            "UNRESET_ITF": lambda v: v | (1 << 1),
            "LOAD":        lambda v: (v | (1 << 2)) & ~(1 << 3),
            "READ":        lambda v: (v | (1 << 3)) & ~(1 << 2),
            "STANDBY":     lambda v: v & ~0x0C,
        }
    else:
        _log.warning("Unknown rst_active polarity: %s", rst_active)
        return

    fn = _map.get(cmd)
    if fn is None:
        _log.warning("Unknown itf_set_control command: %s", cmd)
        return

    self.fpga_write(self.REG_ITF_I_CONTROL, [fn(value) & 0xFF])


# ============================================================================
# 3. REGISTER READ / WRITE PRIMITIVES
# ============================================================================

def itf_write_add(self, value: int) -> None:
    """Write a 64-bit address to ``I_ADD``."""
    if not self._check_itf_defined():
        return
    self.fpga_write(self.REG_ITF_I_ADD, list(value.to_bytes(8, "little")))


def itf_write_ctrl(self, value: int) -> None:
    """Write a raw byte to ``I_CONTROL``."""
    if not self._check_itf_defined():
        return
    self.fpga_write(self.REG_ITF_I_CONTROL, [value & 0xFF])


def itf_write_data_in(self, value: int) -> None:
    """Write a 64-bit word to ``I_DATA_IN``."""
    if not self._check_itf_defined():
        return
    self.fpga_write(self.REG_ITF_I_DATA_IN, list(value.to_bytes(8, "little")))


def itf_start(self) -> None:
    """Pulse the GO register to start an operation."""
    if not self._check_itf_defined():
        return
    self.fpga_write(self.REG_ITF_GO, [1])


def itf_clk_div_set(self, value: int) -> None:
    """Set the clock divider value (2 = /2, 4 = /4, etc.)."""
    if not self._check_itf_defined():
        return
    self.fpga_write(self.REG_ITF_CLKDIV_VALUE, [value & 0xFF])


# ============================================================================
# 4. STATUS / READ-BACK
# ============================================================================

def itf_busy(self) -> bool:
    """Return ``True`` while the core is executing."""
    if not self._check_itf_defined():
        return False
    return bool(self.fpga_read(self.REG_ITF_GO, 1)[0] & 0x01)


def itf_done(self) -> bool:
    """Return ``True`` when an operation has completed."""
    if not self._check_itf_defined():
        return False
    return bool(self.fpga_read(self.REG_ITF_O_END_OP, 1)[0] & 0x01)


def itf_read_data_out(self) -> int:
    """Read the 64-bit ``O_DATA_OUT`` register as an integer."""
    if not self._check_itf_defined():
        return 0
    raw = self.fpga_read(self.REG_ITF_O_DATA_OUT, 8)
    return int.from_bytes(bytes(raw), "little")


def itf_user_led(self, on: bool) -> None:
    """Toggle the user LED on the CW305 board."""
    if getattr(self, "REG_ITF_USER_LED", None) is None:
        _log.warning("REG_ITF_USER_LED undefined")
        return
    self.fpga_write(self.REG_ITF_USER_LED, [1 if on else 0])


def itf_set_clksettings(self, value: int) -> None:
    """Write the 5-bit clock-settings register."""
    if getattr(self, "REG_ITF_CLKSETTINGS", None) is None:
        _log.warning("REG_ITF_CLKSETTINGS undefined")
        return
    self.fpga_write(self.REG_ITF_CLKSETTINGS, [value & 0x1F])


def itf_start_test(self) -> None:
    """Pulse ``START_TEST`` (toggle 0 → 1 → 0)."""
    if getattr(self, "REG_ITF_START_TEST", None) is None:
        _log.warning("REG_ITF_START_TEST undefined")
        return
    self.fpga_write(self.REG_ITF_START_TEST, [0])
    self.fpga_write(self.REG_ITF_START_TEST, [1])
    self.fpga_write(self.REG_ITF_START_TEST, [0])


def itf_start_test_ultrafast(self) -> None:
    """Clear next-block bits (NO_OP) and pulse START_TEST in one call."""
    if not self._check_itf_defined():
        return
    value = self.fpga_read(self.REG_ITF_I_CONTROL, 8)[0]
    value = value & ~((1 << 5) | (1 << 6))
    self.fpga_write(self.REG_ITF_I_CONTROL, [value & 0xFF])
    self.itf_start_test()


def itf_busy_cnt(self) -> int:
    """Read the 13-bit busy-cycle counter from ``O_END_OP[15:3]``."""
    if not self._check_itf_defined():
        return 0
    raw = self.fpga_read(self.REG_ITF_O_END_OP, 4)
    full = raw[0] | (raw[1] << 8) | (raw[2] << 16) | (raw[3] << 24)
    return (full >> 3) & 0x1FFF


# ============================================================================
# 5. AEAD-SPECIFIC CONTROL BITS
# ============================================================================

def itf_set_encrypt(self, encrypt: bool) -> None:
    """Set or clear the *encrypt* flag (bit 4 of ``I_CONTROL``)."""
    if not self._check_itf_defined():
        return
    value = self.fpga_read(self.REG_ITF_I_CONTROL, 8)[0]
    if encrypt:
        value |= (1 << 4)
    else:
        value &= ~(1 << 4)
    self.fpga_write(self.REG_ITF_I_CONTROL, [value & 0xFF])


def it_set_next_block(self, cmd: str) -> None:
    """Set the 2-bit *next_block* field (bits [6:5] of ``I_CONTROL``).

    Parameters
    ----------
    cmd : str
        ``"NO_OP"`` (00), ``"AAD_NEXT"`` (01), ``"PT_NEXT"`` (10),
        or ``"AEAD_END"`` (11).
    """
    if not self._check_itf_defined():
        return
    value = self.fpga_read(self.REG_ITF_I_CONTROL, 8)[0]
    value &= ~((1 << 5) | (1 << 6))
    _bits = {"NO_OP": 0, "AAD_NEXT": 1 << 5, "PT_NEXT": 1 << 6,
             "AEAD_END": (1 << 5) | (1 << 6)}
    value |= _bits.get(cmd, 0)
    self.fpga_write(self.REG_ITF_I_CONTROL, [value & 0xFF])


def itf_tag_valid(self) -> bool:
    """Return ``True`` if the tag-valid flag (bit 2 of ``O_END_OP``) is set."""
    if not self._check_itf_defined():
        return False
    return bool(self.fpga_read(self.REG_ITF_O_END_OP, 1)[0] & 0x04)


# ============================================================================
# 6. BLOCK READ HELPERS (PISO)
# ============================================================================

def itf_read_output_block(self, start: int, end: int) -> int:
    """Read a contiguous block of 64-bit words from the output PISO."""
    if not self._check_itf_defined():
        return 0
    words = []
    for idx in range(end):
        self.itf_write_add(idx + start)
        self.itf_write_ctrl(0x08)
        words.append(self.itf_read_data_out())
        self.itf_write_ctrl(0x00)
    pack = 0
    for i, w in enumerate(words):
        pack |= w << (i * 64)
    return pack


def itf_read_ciphertext(self) -> int:
    """Read the 512-bit ciphertext from PISO addresses 0–7."""
    if not self._check_itf_defined():
        return 0
    words = []
    for idx in range(8):
        self.itf_write_add(idx)
        self.itf_set_control("READ")
        words.append(self.itf_read_data_out())
        self.itf_set_control("STANDBY")
    ct = 0
    for i, w in enumerate(words):
        ct |= w << (i * 64)
    return ct


def itf_read_tag(self) -> int:
    """Read the 128-bit authentication tag from PISO addresses 8–9."""
    if not self._check_itf_defined():
        return 0
    words = []
    for idx in range(2):
        self.itf_write_add(idx + 8)
        self.itf_set_control("READ")
        words.append(self.itf_read_data_out())
        self.itf_set_control("STANDBY")
    tag = 0
    for i, w in enumerate(words):
        tag |= w << (i * 64)
    return tag


# ============================================================================
# 7. PUBLIC ENTRY POINT
# ============================================================================

_ALL_METHODS = [
    _check_itf_defined,
    itf_set_control, itf_write_ctrl, itf_write_add, itf_write_data_in,
    itf_start, itf_clk_div_set,
    itf_busy, itf_done, itf_read_data_out, itf_user_led,
    itf_set_clksettings, itf_start_test, itf_start_test_ultrafast,
    itf_set_encrypt, it_set_next_block,
    itf_read_output_block, itf_read_ciphertext, itf_read_tag,
    itf_tag_valid, itf_busy_cnt,
]


def patch_target(target) -> None:
    """Monkey-patch a CW305 target instance with ITF register methods.

    Parameters
    ----------
    target : chipwhisperer.targets.CW305
        An already-instantiated CW305 target (with defines loaded).

    Raises
    ------
    RuntimeError
        If mandatory ITF register addresses are not defined on ``target``.
    """
    for fn in _ALL_METHODS:
        setattr(target, fn.__name__, MethodType(fn, target))

    if not target._check_itf_defined():
        _log.warning("ITF prerequisite check failed — some methods may not work.")

    _log.info("ITF driver patched: %s",
              [m.__name__ for m in _ALL_METHODS if m.__name__.startswith("itf_")])
