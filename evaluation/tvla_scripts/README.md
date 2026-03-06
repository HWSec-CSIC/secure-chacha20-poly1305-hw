# TVLA Evaluation Scripts

This directory contains scripts for Test Vector Leakage Assessment (TVLA)
using the fixed vs. random t-test methodology.

## Files

| File                | Description                                                |
|---------------------|------------------------------------------------------------|
| `tvla_analysis.py`  | Main TVLA script — computes Welch's t-test on trace sets.  |
| `requirements.txt`  | Python dependencies.                                       |

## Quick Start

```bash
pip install -r requirements.txt
python tvla_analysis.py --fixed traces_fixed.npy --random traces_random.npy --order 1
```

## Trace Format

Traces are expected as NumPy `.npy` files with shape `(N, T)` where:
- `N` = number of traces
- `T` = number of time samples per trace

## Supported Analysis Orders

- `--order 1` : 1st-order (standard Welch's t-test)
- `--order 2` : 2nd-order (centered-product preprocessing)
- `--order 3` : 3rd-order (centered-product preprocessing)
