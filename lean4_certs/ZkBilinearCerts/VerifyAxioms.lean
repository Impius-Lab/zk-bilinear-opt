/-
  ZkBilinearCerts.VerifyAxioms
  Kernel axiom audit across all formal soundness and bilinear optimality theorems.
  Verifies zero `sorryAx`, zero `Lean.ofReduceBool` / `Lean.trustCompiler`, and zero
  user-declared `axiom`s — only standard Lean 4 kernel axioms (`propext`,
  `Classical.choice`, `Quot.sound`) or pure constructive kernel terms (`no axioms`).
-/

import ZkBilinearCerts.Qm31Algebraic
import ZkBilinearCerts.M31Overflow
import ZkBilinearCerts.CrtSoundness

-- 1. Qm31Algebraic.lean: Universal Ring & Modular M31 Identities
#print axioms ZkBilinearCerts.qm31_schoolbook_i_sq
#print axioms ZkBilinearCerts.qm31_schoolbook_u_sq
#print axioms ZkBilinearCerts.qm31_schoolbook_comm
#print axioms ZkBilinearCerts.qm31_schoolbook_assoc
#print axioms ZkBilinearCerts.qm31_karatsuba9_eq_schoolbook
#print axioms ZkBilinearCerts.qm31_quartic_isomorphism
#print axioms ZkBilinearCerts.inv12_mod_m31_cert
#print axioms ZkBilinearCerts.inv24_mod_m31_cert
#print axioms ZkBilinearCerts.inv120_mod_m31_cert
#print axioms ZkBilinearCerts.qm31_rank7_scaled120_eq_schoolbook
#print axioms ZkBilinearCerts.qm31_rank7_mod_m31_eq_schoolbook
#print axioms ZkBilinearCerts.qm31_square_rank6_eq_schoolbook

-- 2. M31Overflow.lean: Mersenne-31 Bitwise Fold & Delayed-u64 Non-Overflow
#print axioms ZkBilinearCerts.m31_fold_bitwise_eq_arith
#print axioms ZkBilinearCerts.m31_fold_mod_eq
#print axioms ZkBilinearCerts.m31_fold2_mod_eq
#print axioms ZkBilinearCerts.m31_fold2_bound
#print axioms ZkBilinearCerts.m31_fold2_max_attained
#print axioms ZkBilinearCerts.m31_reduce64_eq_mod
#print axioms ZkBilinearCerts.m31_reduce64_canonical
#print axioms ZkBilinearCerts.m31_reduce64_branchless_sound_and_canonical
#print axioms ZkBilinearCerts.qm31_dot4_redundant_lt_u64
#print axioms ZkBilinearCerts.qm31_dot4_canonical_lt_u64
#print axioms ZkBilinearCerts.qm31_dot4_reduce64_eq_schoolbook
#print axioms ZkBilinearCerts.five_unreduced_m31_products_gt_u64
#print axioms ZkBilinearCerts.stwo_outer_karatsuba_u64_lt_u64
#print axioms ZkBilinearCerts.qm31_rank7_u64_bounds

-- 3. CrtSoundness.lean: Non-Native CRT Forgery Witnesses & Quotient-Bit Soundness
#print axioms ZkBilinearCerts.babybear_b22_unmasked_forgery_cert
#print axioms ZkBilinearCerts.babybear_single_limb_unmasked_forgery_cert
#print axioms ZkBilinearCerts.ext_gcd_nat_bezout
#print axioms ZkBilinearCerts.coprime_mul_dvd_of_emod_zero
#print axioms ZkBilinearCerts.crt_quotient_soundness
#print axioms ZkBilinearCerts.crt_quotient_unique_witness
#print axioms ZkBilinearCerts.babybear_b22_masked_quobits_sound
