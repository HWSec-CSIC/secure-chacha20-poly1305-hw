# Secure & Scalable ChaCha20-Poly1305 Hardware Accelerator

This repository contains an open-source, highly configurable RTL implementation of the ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) algorithm. It provides a dual-architecture approach tailored for different security requirements:

* **Standard Core:** A flexible, high-throughput architecture optimized for resource-constrained IoT devices.
* **Secure Core:** A 1st-order DPA-secure variant featuring a fully masked datapath (Threshold Implementations, SDRR, and blinded Karatsuba multipliers) designed for hostile edge deployments.

## Repository Structure

```
secure-chacha20-poly1305-hw/
├── README.md                            # Main project documentation.
├── LICENSE                              # Open-source license (MIT).
├── .gitignore                           # Ignoring simulator and synthesis junk files.
│
├── rtl/                                 # Synthesizable design files (Verilog).
│   ├── standard/                        # Base architecture (unprotected).
│   ├── secure/                          # Masked variant (TI, SDRR, blinded Karatsuba).
│   ├── cw305_interface/                 # CW305 board interface (USB, clocks, registers).
│   └── common/                          # Shared modules used by both architectures.
│
├── tb/                                  # Testbenches and verification environments.
│   ├── standard_tb/                     # Testbench for the standard version.
│   └── secure_tb/                       # Testbench for the secure version.
│
├── src/                                 # Python support modules for scripts.
│   ├── config.py                        # Centralised paths and parameters.
│   ├── itf_driver.py                    # CW305 ITF register driver.
│   ├── aead_helpers.py                  # AEAD packing and test-vector routines.
│   └── tvla_core.py                     # Online Welch's t-test implementation.
│
├── bitstreams/                          # Pre-compiled files ready for FPGA programming.
│   ├── cw305_aead_unmasked.bit          # Bitstream for the standard unprotected core.
│   └── cw305_aead_masked.bit            # Bitstream for the DPA-secure masked core.
│
└── scripts/                             # Jupyter notebooks for TVLA evaluation.
    ├── 01_capture_aead_masked.ipynb     # Trace acquisition for the masked core.
    ├── 02_capture_aead_unmasked.ipynb   # Trace acquisition for the unmasked core.
    └── 03_tvla_compute.ipynb            # TVLA (Welch's t-test) computation.
```

## Pre-compiled Bitstreams

For immediate testing and deployment, the `bitstreams/` directory contains pre-compiled `.bit` files for both the standard and secure cores.

| File                        | Description                                      |
|-----------------------------|--------------------------------------------------|
| `cw305_aead_unmasked.bit`   | Standard (unprotected) ChaCha20-Poly1305 core.   |
| `cw305_aead_masked.bit`     | 1st-order DPA-secure masked core.                |

### Hardware Target

- **FPGA Board:** NewAE CW305
- **FPGA Family:** Xilinx Artix-7
- **Part Number:** XC7A100T-1CSG324C
- **Toolchain:** Vivado 2023.2
- **Target Frequency:** 100 MHz

### Programming the FPGA

Load a pre-compiled bitstream onto the CW305 board using the Vivado Hardware Manager or the ChipWhisperer Python API. To re-synthesize for a different FPGA family or board, use the RTL sources in the `rtl/` directory with your preferred EDA toolchain.

## Architecture Overview

### Standard Core

The standard (unprotected) core implements the full ChaCha20-Poly1305 AEAD construction as specified in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439). Key features include:

- Configurable number of quarter-round (QR) units for throughput/area trade-offs.
- Pipelined Poly1305 MAC computation with a fully unrolled Karatsuba multiplier.
- AXI4-Stream compliant interface for seamless SoC integration.

### Secure Core

The secure (masked) core provides 1st-order DPA resistance through:

- **Threshold Implementations (TI):** All non-linear operations are decomposed into share-based computations satisfying the non-completeness, correctness, and uniformity properties.
- **Shared Domain Re-Randomization (SDRR):** Fresh randomness is injected at critical pipeline stages to maintain security margins against higher-order leakage.
- **Blinded Karatsuba Multiplier:** The Poly1305 field multiplication is protected using a multiplicative blinding scheme integrated with a Karatsuba decomposition.

## Getting Started

### Prerequisites

- A Verilog/SystemVerilog simulator (e.g., Vivado Simulator, ModelSim, Verilator).
- Xilinx Vivado Design Suite (for synthesis and bitstream generation).
- Python 3.8+ (for TVLA evaluation scripts).

### Running the Testbenches

1. **Standard core testbench:**
   ```bash
   cd tb/standard_tb/
   # Use your simulator of choice, e.g.:
   # vivado -mode batch -source run_sim.tcl
   ```

2. **Secure core testbench:**
   ```bash
   cd tb/secure_tb/
   # Use your simulator of choice, e.g.:
   # vivado -mode batch -source run_sim.tcl
   ```

## TVLA Evaluation Scripts

The `scripts/` directory contains Jupyter notebooks for Test Vector Leakage Assessment (TVLA) using the fixed vs. random t-test methodology with the ChipWhisperer CW305 platform.

| Notebook                            | Description                                                |
|-------------------------------------|------------------------------------------------------------|
| `01_capture_aead_masked.ipynb`      | Trace acquisition for the masked (secure) core.            |
| `02_capture_aead_unmasked.ipynb`    | Trace acquisition for the unmasked (standard) core.        |
| `03_tvla_compute.ipynb`             | Welch's t-test computation and plotting.                   |

### Quick Start

```bash
cd scripts/
jupyter notebook
```

### Trace Format

Traces are expected as NumPy `.npy` files with shape `(N, T)` where:
- `N` = number of traces
- `T` = number of time samples per trace

## License

> *License details will be added after the blind-review process.*

## Citation

If you use this work in your research, please cite:

> *Citation details will be added after the blind-review process.*
