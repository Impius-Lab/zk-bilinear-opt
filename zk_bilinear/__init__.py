"""zk_bilinear: Exact Finite-Field Bilinear Rank Certifier & ZK Circuit Optimizer."""

from .cost_models import (
    EmulatedLimbCost,
    FullScheduleCost,
    NativeCircuitCost,
    compute_emulated_limb_cost,
    compute_native_cost,
    evaluate_full_cost,
    verify_emulated_witness_bounds,
)
from .fields import (
    BABYBEAR_PRIME,
    BLS12_381_PRIME,
    BN254_PRIME,
    EXTENSION_SPECS,
    GOLDILOCKS_PRIME,
    KOALABEAR_PRIME,
    M31_PRIME,
    PRIMES,
    ExtensionSpec,
    is_irreducible_rabin,
    is_prime,
)
from .pareto_search import (
    SCHEDULE_SUITE,
    compute_pareto_frontier,
    get_optimal_native_schedule,
    get_schedules_for_target,
)
from .tensor_cert import (
    BilinearSchedule,
    CertificateReport,
    compute_w_fp,
    evaluate_schedule_fp,
    execute_native_word_checked,
    theoretical_peak_native_bits,
    verify_schedule_certificate,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "M31_PRIME",
    "BABYBEAR_PRIME",
    "KOALABEAR_PRIME",
    "GOLDILOCKS_PRIME",
    "BN254_PRIME",
    "BLS12_381_PRIME",
    "PRIMES",
    "ExtensionSpec",
    "EXTENSION_SPECS",
    "is_prime",
    "is_irreducible_rabin",
    "BilinearSchedule",
    "CertificateReport",
    "compute_w_fp",
    "evaluate_schedule_fp",
    "execute_native_word_checked",
    "theoretical_peak_native_bits",
    "verify_schedule_certificate",
    "NativeCircuitCost",
    "EmulatedLimbCost",
    "FullScheduleCost",
    "compute_native_cost",
    "compute_emulated_limb_cost",
    "evaluate_full_cost",
    "verify_emulated_witness_bounds",
    "SCHEDULE_SUITE",
    "get_schedules_for_target",
    "get_optimal_native_schedule",
    "compute_pareto_frontier",
]
