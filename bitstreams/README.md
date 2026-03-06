# Bitstreams

This directory contains pre-compiled `.bit` files for the Xilinx Artix-7 FPGA.

| File                    | Description                                      |
|-------------------------|--------------------------------------------------|
| `standard_artix7.bit`   | Standard (unprotected) ChaCha20-Poly1305 core.   |
| `secure_artix7.bit`     | 1st-order DPA-secure masked core.                |

## Hardware Target

- **FPGA Family:** Xilinx Artix-7
- **Part Number:** XC7A100T-1CSG324C *(update with your exact part)*
- **Toolchain:** Vivado 2023.2
- **Frequency:** 100 MHz (post-place-and-route timing met)

## Usage

Program the FPGA using Vivado Hardware Manager or the command line:

```bash
vivado -mode batch -source program_fpga.tcl -tclargs standard_artix7.bit
```

## Note

If you are targeting a different FPGA family or board, re-synthesize from the
RTL sources in the `rtl/` directory using your preferred EDA toolchain.

> **Blind-review note:** Actual `.bit` files are not included in this
> anonymous submission to keep the repository lightweight. They will be
> provided in the camera-ready release or upon request.
