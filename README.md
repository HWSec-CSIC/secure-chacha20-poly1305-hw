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
├── rtl/                                 # Synthesizable design files (SystemVerilog).
│   ├── standard/                        # Base architecture (unprotected).
│   ├── secure/                          # Masked variant (TI, SDRR, blinded Karatsuba).
│   └── common/                          # Shared modules used by both architectures.
│
├── tb/                                  # Testbenches and verification environments.
│   ├── standard_tb/                     # Testbench for the standard version.
│   └── secure_tb/                       # Testbench for the secure version.
│
├── bitstreams/                          # Pre-compiled files ready for FPGA programming.
│   ├── cw305_aead_unmasked.bit          # Bitstream for the standard unprotected core.
│   └── cw305_aead_masked.bit            # Bitstream for the DPA-secure masked core.
│
└── evaluation/                          # Scripts and physical evaluation data.
    └── tvla_scripts/                    # Python scripts for TVLA (t-test) computation.
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
- **Frequency:** 100 MHz (post-place-and-route timing met)

### Programming the FPGA

Load the pre-compiled bitstream onto the CW305 board:

```bash
vivado -mode batch -source program_fpga.tcl -tclargs bitstreams/cw305_aead_unmasked.bit
```

If you are targeting a different FPGA family or board, re-synthesize from the RTL sources in the `rtl/` directory using your preferred EDA toolchain.

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

- A Verilog/SystemVerilog simulator (e.g., Vivado Simulator, ModelSim, VCS).
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

The `evaluation/tvla_scripts/` directory contains scripts for Test Vector Leakage Assessment (TVLA) using the fixed vs. random t-test methodology.

| File                | Description                                                |
|---------------------|------------------------------------------------------------|
| `tvla_analysis.py`  | Main TVLA script — computes Welch's t-test on trace sets.  |
| `requirements.txt`  | Python dependencies.                                       |

### Quick Start

```bash
cd evaluation/tvla_scripts/
pip install -r requirements.txt
python tvla_analysis.py --fixed traces_fixed.npy --random traces_random.npy --order 1
```

### Trace Format

Traces are expected as NumPy `.npy` files with shape `(N, T)` where:
- `N` = number of traces
- `T` = number of time samples per trace

### Supported Analysis Orders

- `--order 1` : 1st-order (standard Welch's t-test)
- `--order 2` : 2nd-order (centered-product preprocessing)
- `--order 3` : 3rd-order (centered-product preprocessing)

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Citation

If you use this work in your research, please cite:

> *Citation details will be added after the blind-review process.*
