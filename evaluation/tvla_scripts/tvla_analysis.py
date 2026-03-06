#!/usr/bin/env python3
# =============================================================================
# tvla_analysis.py
# Test Vector Leakage Assessment (TVLA) — Fixed vs. Random t-test
#
# Computes Welch's t-test on side-channel traces to evaluate whether the
# DPA-secure core exhibits statistically significant leakage.
#
# Usage:
#   python tvla_analysis.py --fixed <fixed_traces.npy> \
#                           --random <random_traces.npy> \
#                           --order 1 \
#                           --output tvla_results.png
# =============================================================================

import argparse
import sys
from pathlib import Path

import numpy as np


def welch_ttest(traces_fixed: np.ndarray, traces_random: np.ndarray) -> np.ndarray:
    """
    Compute Welch's t-statistic for each time sample.

    Parameters
    ----------
    traces_fixed : np.ndarray, shape (N_fixed, T)
        Traces acquired with a fixed input.
    traces_random : np.ndarray, shape (N_random, T)
        Traces acquired with random inputs.

    Returns
    -------
    t_values : np.ndarray, shape (T,)
        Welch's t-statistic per time sample.
    """
    n1 = traces_fixed.shape[0]
    n2 = traces_random.shape[0]

    mean1 = np.mean(traces_fixed, axis=0)
    mean2 = np.mean(traces_random, axis=0)

    var1 = np.var(traces_fixed, axis=0, ddof=1)
    var2 = np.var(traces_random, axis=0, ddof=1)

    t_values = (mean1 - mean2) / np.sqrt(var1 / n1 + var2 / n2)

    return t_values


def higher_order_preprocess(traces: np.ndarray, order: int) -> np.ndarray:
    """
    Apply centered-product preprocessing for higher-order TVLA.

    Parameters
    ----------
    traces : np.ndarray, shape (N, T)
    order : int
        Order of the analysis (1 = standard, 2 = 2nd-order, etc.).

    Returns
    -------
    processed : np.ndarray, shape (N, T)
    """
    if order == 1:
        return traces

    # Center traces (subtract mean per time sample)
    centered = traces - np.mean(traces, axis=0)

    # Raise to the power of the order
    processed = np.power(centered, order)

    return processed


def main():
    parser = argparse.ArgumentParser(
        description="TVLA (t-test) leakage assessment for side-channel traces."
    )
    parser.add_argument(
        "--fixed", type=str, required=True,
        help="Path to fixed-input traces (.npy format)."
    )
    parser.add_argument(
        "--random", type=str, required=True,
        help="Path to random-input traces (.npy format)."
    )
    parser.add_argument(
        "--order", type=int, default=1, choices=[1, 2, 3],
        help="Order of the t-test (1=1st-order, 2=2nd-order, etc.)."
    )
    parser.add_argument(
        "--threshold", type=float, default=4.5,
        help="Threshold for t-value (default: 4.5, corresponds to p < 1e-5)."
    )
    parser.add_argument(
        "--output", type=str, default="tvla_results.png",
        help="Output filename for the t-test plot."
    )
    args = parser.parse_args()

    # Load traces
    fixed_path = Path(args.fixed)
    random_path = Path(args.random)

    if not fixed_path.exists():
        print(f"Error: Fixed traces file not found: {fixed_path}", file=sys.stderr)
        sys.exit(1)
    if not random_path.exists():
        print(f"Error: Random traces file not found: {random_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading fixed traces from:  {fixed_path}")
    traces_fixed = np.load(str(fixed_path))

    print(f"Loading random traces from: {random_path}")
    traces_random = np.load(str(random_path))

    print(f"Fixed traces shape:  {traces_fixed.shape}")
    print(f"Random traces shape: {traces_random.shape}")

    # Preprocessing for higher-order analysis
    if args.order > 1:
        print(f"Applying {args.order}-order centered-product preprocessing...")
        traces_fixed = higher_order_preprocess(traces_fixed, args.order)
        traces_random = higher_order_preprocess(traces_random, args.order)

    # Compute t-test
    print("Computing Welch's t-test...")
    t_values = welch_ttest(traces_fixed, traces_random)

    # Report results
    max_t = np.max(np.abs(t_values))
    leaky_samples = np.sum(np.abs(t_values) > args.threshold)
    total_samples = len(t_values)

    print(f"\n{'='*60}")
    print(f"TVLA Results ({args.order}-order)")
    print(f"{'='*60}")
    print(f"  Max |t-value|:     {max_t:.4f}")
    print(f"  Threshold:         {args.threshold}")
    print(f"  Leaky samples:     {leaky_samples} / {total_samples}")

    if max_t > args.threshold:
        print(f"  Result:            LEAKAGE DETECTED")
    else:
        print(f"  Result:            NO LEAKAGE DETECTED (PASS)")
    print(f"{'='*60}\n")

    # Plot results
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(14, 5))
        ax.plot(t_values, linewidth=0.5, color="steelblue")
        ax.axhline(y=args.threshold,  color="red", linestyle="--", linewidth=1,
                    label=f"+{args.threshold}")
        ax.axhline(y=-args.threshold, color="red", linestyle="--", linewidth=1,
                    label=f"-{args.threshold}")
        ax.set_xlabel("Time Sample")
        ax.set_ylabel("t-value")
        ax.set_title(f"TVLA Fixed vs. Random ({args.order}-order t-test)")
        ax.legend(loc="upper right")
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(args.output, dpi=200)
        print(f"Plot saved to: {args.output}")

    except ImportError:
        print("matplotlib not available — skipping plot generation.")


if __name__ == "__main__":
    main()
