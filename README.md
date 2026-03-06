# Secure & Scalable ChaCha20-Poly1305 Hardware Accelerator

This repository contains an open-source, highly configurable RTL implementation of the ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD) algorithm. It provides a dual-architecture approach tailored for different security requirements:

* **Standard Core:** A flexible, high-throughput architecture optimized for resource-constrained IoT devices.
* **Secure Core:** A 1st-order DPA-secure variant featuring a fully masked datapath (Threshold Implementations, SDRR, and blinded Karatsuba multipliers) designed for hostile edge deployments.

## Repository Structure

```
secure-chacha20-poly1305-hw/
├── README.md                 # Main project documentation, architecture details, and usage.
├── LICENSE                   # Open-source license (MIT).
├── .gitignore                # Essential for ignoring simulator and synthesis junk files.
│
├── rtl/                      # Synthesizable design files (VHDL / Verilog / SystemVerilog).
│   ├── standard/             # Source code for the base architecture (unprotected).
│   ├── secure/               # Source code for the masked variant (TI, SDRR, blinded Karatsuba).
│   └── common/               # Shared modules used by both architectures.
│
├── tb/                       # Testbenches and verification environments.
│   ├── standard_tb/          # Testbench for the standard version.
│   └── secure_tb/            # Testbench for the secure version (includes test vectors).
│
├── bitstreams/               # Pre-compiled files ready for FPGA programming.
│   ├── standard_artix7.bit   # Bitstream for the standard unprotected core.
│   └── secure_artix7.bit     # Bitstream for the DPA-secure masked core.
│
└── evaluation/               # Scripts and physical evaluation data.
    └── tvla_scripts/         # Python/MATLAB scripts used for the TVLA (t-test) computation.
```

## Pre-compiled Bitstreams

For immediate testing and deployment, the `bitstreams/` directory contains pre-compiled `.bit` files for both the standard and secure cores.

**Hardware Target Note:** These bitstreams were specifically synthesized and routed for the **Xilinx Artix-7 FPGA** (e.g., `XC7A100T`). If you are targeting a different FPGA family or vendor, please re-synthesize the source files located in the `rtl/` directory using your preferred toolchain.

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

### Programming the FPGA

Load the pre-compiled bitstream onto a compatible Artix-7 board:

```bash
vivado -mode batch -source program_fpga.tcl -tclargs bitstreams/standard_artix7.bit
```

### Running TVLA Evaluation

```bash
cd evaluation/tvla_scripts/
python tvla_analysis.py --traces <path_to_traces> --order 1
```

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Citation

If you use this work in your research, please cite:

> *Citation details will be added after the blind-review process.*
