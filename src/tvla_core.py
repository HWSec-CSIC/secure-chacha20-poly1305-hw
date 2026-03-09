"""
tvla_core.py — Online statistical accumulators and Welch's t-test.

This module implements memory-efficient, single-pass computation of
arbitrary-order central moments and the associated Welch t-statistic,
following the methodology of:

    Schneider & Moradi, "Leakage Assessment Methodology — A Clear Road-
    map for Side-Channel Evaluations," CHES 2015.

The ``OnlineTVLA`` class accumulates raw power sums in a streaming
fashion so that million-trace datasets can be processed without
materialising the full array in memory.
"""

from __future__ import annotations

import numpy as np
from scipy.special import comb
import scipy.stats as ss
from tqdm.auto import tqdm


# ============================================================================
# 1. ONLINE MOMENT ACCUMULATOR
# ============================================================================

class OnlineTVLA:
    """Streaming accumulator for raw power sums up to order ``2 * max_order``.

    After feeding *N* trace vectors of dimension *S*, any central moment
    up to the configured order can be recovered in O(S) time.

    Parameters
    ----------
    n_samples : int
        Number of sample points per trace (dimension *S*).
    max_order : int, optional
        Maximum statistical order to support.  Default ``1`` (mean-only,
        first-order TVLA).  Set to ``2`` for variance-based (second-order)
        leakage detection.
    """

    def __init__(self, n_samples: int, max_order: int = 1) -> None:
        self.n_samples = n_samples
        self.max_order = max_order
        self.n_total: int = 0
        self.sums: list[np.ndarray] = [
            np.zeros(n_samples, dtype="float64") for _ in range(2 * max_order)
        ]

    # ------------------------------------------------------------------ #
    def update(self, chunk: np.ndarray) -> None:
        """Ingest a batch of traces.

        Parameters
        ----------
        chunk : ndarray, shape (B, S)
            Batch of *B* power traces, each of length *S*.
        """
        batch_size = chunk.shape[0]
        self.n_total += batch_size
        curr_pow = chunk.astype("float64")
        for k in range(2 * self.max_order):
            self.sums[k] += np.sum(curr_pow, axis=0)
            if k < (2 * self.max_order) - 1:
                curr_pow *= chunk

    # ------------------------------------------------------------------ #
    def get_raw_moment(self, k: int) -> np.ndarray | float:
        r"""Return the *k*-th raw moment  :math:`\hat{\mu}'_k = \frac{1}{N}\sum x^k`.

        Parameters
        ----------
        k : int
            Moment order (0 returns ``1.0``).
        """
        if k == 0:
            return 1.0
        return self.sums[k - 1] / self.n_total

    # ------------------------------------------------------------------ #
    def get_central_moment(self, k: int) -> np.ndarray:
        r"""Return the *k*-th central moment via the binomial expansion.

        .. math::
            \mu_k = \sum_{i=0}^{k} \binom{k}{i}\,(-1)^{k-i}\,\mu'_i\,{\mu'_1}^{k-i}
        """
        mu1 = self.get_raw_moment(1)
        res = np.zeros(self.n_samples, dtype="float64")
        for i in range(k + 1):
            term = comb(k, i) * ((-1) ** (k - i))
            term *= self.get_raw_moment(i)
            term *= mu1 ** (k - i)
            res += term
        return res


# ============================================================================
# 2. WELCH'S T-TEST (SNAPSHOT)
# ============================================================================

def calc_t_snapshot(
    fixed_obj: OnlineTVLA,
    random_obj: OnlineTVLA,
    order: int = 1,
) -> np.ndarray:
    """Compute the Welch t-statistic from two ``OnlineTVLA`` accumulators.

    For ``order == 1`` the test compares *means* (first-order, non-specific
    TVLA).  For ``order >= 2`` it compares *central moments* of the specified
    order, enabling higher-order leakage detection on masked implementations.

    Parameters
    ----------
    fixed_obj : OnlineTVLA
        Accumulator for the *fixed*-input trace set.
    random_obj : OnlineTVLA
        Accumulator for the *random*-input trace set.
    order : int, optional
        Statistical order of the test.  Default ``1``.

    Returns
    -------
    t : ndarray, shape (S,)
        Per-sample Welch t-statistic.
    """
    N_f = fixed_obj.n_total
    N_r = random_obj.n_total
    if N_f == 0 or N_r == 0:
        return np.zeros(fixed_obj.n_samples)

    if order == 1:
        mu_d_f = fixed_obj.get_raw_moment(1)
        mu_d_r = random_obj.get_raw_moment(1)
        var_d_f = fixed_obj.get_central_moment(2)
        var_d_r = random_obj.get_central_moment(2)
    else:
        mu_d_f = fixed_obj.get_central_moment(order)
        mu_d_r = random_obj.get_central_moment(order)
        mu_2d_f = fixed_obj.get_central_moment(2 * order)
        mu_2d_r = random_obj.get_central_moment(2 * order)
        var_d_f = mu_2d_f - mu_d_f**2
        var_d_r = mu_2d_r - mu_d_r**2

    var_d_f = np.maximum(var_d_f, 0)
    var_d_r = np.maximum(var_d_r, 0)

    denominator = np.sqrt((var_d_f / N_f) + (var_d_r / N_r))
    numerator = mu_d_f - mu_d_r
    return np.divide(
        numerator, denominator,
        out=np.zeros_like(numerator),
        where=denominator != 0,
    )


# ============================================================================
# 3. TWO-PASS STREAMING T-TEST (SIMPLE, MEAN-ONLY)
# ============================================================================

def calculate_stats_online(
    dataset,
    n_limit: int,
    chunk_size: int = 5000,
    desc: str = "Processing",
) -> tuple[int, np.ndarray, np.ndarray]:
    """Compute mean and variance of an HDF5 dataset in a single streaming pass.

    Uses the Welford-style two-sum approach for numerical stability.

    Parameters
    ----------
    dataset : h5py.Dataset
        2-D dataset of shape ``(N, S)`` stored on disk.
    n_limit : int
        Maximum number of traces to consume (for balanced TVLA).
    chunk_size : int, optional
        I/O granularity.
    desc : str, optional
        Progress-bar description.

    Returns
    -------
    n : int
        Number of traces actually consumed.
    mean : ndarray, shape (S,)
    var : ndarray, shape (S,)
        Sample variance (Bessel-corrected, ``ddof=1``).
    """
    len_trace = dataset.shape[1]
    acc_sum = np.zeros(len_trace, dtype=np.float64)
    acc_sq_sum = np.zeros(len_trace, dtype=np.float64)

    with tqdm(total=n_limit, desc=desc, unit=" traces") as pbar:
        for i in range(0, n_limit, chunk_size):
            end = min(i + chunk_size, n_limit)
            chunk = dataset[i:end].astype(np.float64)
            acc_sum += np.sum(chunk, axis=0)
            acc_sq_sum += np.sum(chunk**2, axis=0)
            pbar.update(end - i)
            del chunk

    mean = acc_sum / n_limit
    var = (acc_sq_sum - (acc_sum**2 / n_limit)) / (n_limit - 1)
    return n_limit, mean, var


# ============================================================================
# 4. MINI-P (BONFERRONI) THRESHOLD
# ============================================================================

def compute_threshold_minip(
    n_samples: int,
    alpha_global: float = 1e-5,
) -> float:
    r"""Bonferroni-corrected significance threshold (two-sided normal).

    The per-sample significance level is:

    .. math::
        \alpha_\text{local} = 1 - (1 - \alpha_\text{global})^{1/S}

    and the threshold is the corresponding quantile of the standard normal.

    Parameters
    ----------
    n_samples : int
        Total number of sample points *S* (number of independent tests).
    alpha_global : float, optional
        Family-wise error rate.  Default ``1e-5``.

    Returns
    -------
    threshold : float
        Positive threshold value; leakage is declared when ``|t| > threshold``.
    """
    alpha_local = 1 - (1 - alpha_global) ** (1 / n_samples)
    return float(ss.norm.ppf(1 - alpha_local / 2))
