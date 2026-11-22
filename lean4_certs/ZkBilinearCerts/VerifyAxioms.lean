/-
  ZkBilinearCerts.VerifyAxioms
  Kernel axiom audit across all 107 formal soundness and bilinear optimality theorems
  spanning all 5 modules (`Qm31Algebraic`, `M31Overflow`, `CrtSoundness`,
  `Bls12_377Soundness`, and `PastaBls12_381Crt`).
  Verifies zero `sorryAx`, zero `Lean.ofReduceBool` / `Lean.trustCompiler`, and zero
  user-declared `axiom`s — only standard Lean 4 kernel axioms (`propext`,
  `Classical.choice`, `Quot.sound`) or pure constructive kernel terms (`no axioms`).
-/

import ZkBilinearCerts.Qm31Algebraic
import ZkBilinearCerts.M31Overflow
import ZkBilinearCerts.CrtSoundness
import ZkBilinearCerts.Bls12_377Soundness
import ZkBilinearCerts.PastaBls12_381Crt

-- 1. Qm31Algebraic.lean (21 theorems): Universal Ring & Modular M31 Identities
#print axioms ZkBilinearCerts.qm31_schoolbook_one_left
#print axioms ZkBilinearCerts.qm31_schoolbook_one_right
#print axioms ZkBilinearCerts.qm31_schoolbook_i_sq
#print axioms ZkBilinearCerts.qm31_schoolbook_u_sq
#print axioms ZkBilinearCerts.qm31_schoolbook_comm
#print axioms ZkBilinearCerts.qm31_schoolbook_assoc
#print axioms ZkBilinearCerts.qm31_karatsuba9_eq_schoolbook
#print axioms ZkBilinearCerts.qm31_karatsuba9_c0_eq
#print axioms ZkBilinearCerts.qm31_karatsuba9_c1_eq
#print axioms ZkBilinearCerts.qm31_karatsuba9_c2_eq
#print axioms ZkBilinearCerts.qm31_karatsuba9_c3_eq
#print axioms ZkBilinearCerts.from_to_simple_quartic
#print axioms ZkBilinearCerts.to_from_simple_quartic
#print axioms ZkBilinearCerts.qm31_quartic_isomorphism
#print axioms ZkBilinearCerts.inv12_mod_m31_cert
#print axioms ZkBilinearCerts.inv24_mod_m31_cert
#print axioms ZkBilinearCerts.inv120_mod_m31_cert
#print axioms ZkBilinearCerts.qm31_rank7_scaled120_eq_schoolbook
#print axioms ZkBilinearCerts.cancel_120_mod_m31
#print axioms ZkBilinearCerts.qm31_rank7_mod_m31_eq_schoolbook
#print axioms ZkBilinearCerts.qm31_square_rank6_eq_schoolbook

-- 2. M31Overflow.lean (16 theorems): Mersenne-31 Bitwise Fold & Delayed-u64 Non-Overflow
#print axioms ZkBilinearCerts.m31_fold_bitwise_eq_arith
#print axioms ZkBilinearCerts.m31_fold_mod_eq
#print axioms ZkBilinearCerts.m31_fold_bitwise_mod_eq
#print axioms ZkBilinearCerts.m31_fold2_mod_eq
#print axioms ZkBilinearCerts.m31_fold_step1_bound
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

-- 3. CrtSoundness.lean (9 theorems): Non-Native CRT Forgery Witnesses & Quotient-Bit Soundness
#print axioms ZkBilinearCerts.babybear_b22_unmasked_forgery_cert
#print axioms ZkBilinearCerts.babybear_single_limb_unmasked_forgery_cert
#print axioms ZkBilinearCerts.ext_gcd_nat_bezout
#print axioms ZkBilinearCerts.bezout_of_int_gcd_eq_one
#print axioms ZkBilinearCerts.coprime_mul_dvd_of_emod_zero
#print axioms ZkBilinearCerts.eq_zero_of_mul_bounded
#print axioms ZkBilinearCerts.crt_quotient_soundness
#print axioms ZkBilinearCerts.crt_quotient_unique_witness
#print axioms ZkBilinearCerts.babybear_b22_masked_quobits_sound

-- 4. Bls12_377Soundness.lean (38 theorems): Aleo BLS12-377 Lazy Montgomery, W^12+5, Karabina & Fr CRT-30
#print axioms ZkBilinearCerts.q_bls12_377_limbs_and_dec_eq
#print axioms ZkBilinearCerts.q_bls12_377_bit_bounds
#print axioms ZkBilinearCerts.r_bls12_377_limbs_and_hex_eq
#print axioms ZkBilinearCerts.r_bls12_377_bit_bounds
#print axioms ZkBilinearCerts.bls12_377_mont_headroom
#print axioms ZkBilinearCerts.bls12_377_peak136_lt_mont_bound
#print axioms ZkBilinearCerts.fq2_unred_mul_sound_and_bounded
#print axioms ZkBilinearCerts.fq6_unred_mul_bounded
#print axioms ZkBilinearCerts.fq6_unred_mul_by_01_bounded
#print axioms ZkBilinearCerts.fq12_lazy_mul_by_034_bounded
#print axioms ZkBilinearCerts.fq12_lazy_mul_by_014_bounded
#print axioms ZkBilinearCerts.fq12_lazy_mul_bounded
#print axioms ZkBilinearCerts.bls12_377_lazy_mont_all_schedules_canonical
#print axioms ZkBilinearCerts.bls12_377_end_to_end_canonical_lt_mont_bound
#print axioms ZkBilinearCerts.perm_bls12_377_fp12_involutive
#print axioms ZkBilinearCerts.perm_bls12_377_fp12_bijective
#print axioms ZkBilinearCerts.perm12_bls377_apply_involutive
#print axioms ZkBilinearCerts.bls12_377_w12_plus_5_isomorphism
#print axioms ZkBilinearCerts.bls12_377_w12_plus_5_to_monomial_hom
#print axioms ZkBilinearCerts.cyc_fp12_mul_eq_snarkvm_tower
#print axioms ZkBilinearCerts.cyc_fp12_mul_adj_universal
#print axioms ZkBilinearCerts.cyc_fp12_mul_comm
#print axioms ZkBilinearCerts.cyc_fp12_mul_one_left
#print axioms ZkBilinearCerts.cyc_fp12_mul_one_right
#print axioms ZkBilinearCerts.fp4_add_comm
#print axioms ZkBilinearCerts.fp4_add_assoc
#print axioms ZkBilinearCerts.fp4_mul_assoc
#print axioms ZkBilinearCerts.fp4_left_distrib
#print axioms ZkBilinearCerts.fp4_right_distrib
#print axioms ZkBilinearCerts.fp4_mul_s_add
#print axioms ZkBilinearCerts.fp4_mul_left_s
#print axioms ZkBilinearCerts.fp4_mul_right_s
#print axioms ZkBilinearCerts.cyc_fp12_mul_assoc
#print axioms ZkBilinearCerts.cyclotomic_adj_eq_conj
#print axioms ZkBilinearCerts.granger_scott_square_eq_fp12_square
#print axioms ZkBilinearCerts.karabina_square_eq_fp12_square
#print axioms ZkBilinearCerts.karabina_decompression_universal
#print axioms ZkBilinearCerts.aleo_fr_crt30_carry_nonwrap_vs_rank23

-- 5. PastaBls12_381Crt.lean (23 theorems): Zcash Pasta & BLS12-381 Isomorphisms & CRT Uniqueness
#print axioms ZkBilinearCerts.p_pallas_limbs_and_dec_eq
#print axioms ZkBilinearCerts.p_pallas_bit_bounds
#print axioms ZkBilinearCerts.q_vesta_limbs_and_dec_eq
#print axioms ZkBilinearCerts.q_vesta_bit_bounds
#print axioms ZkBilinearCerts.p_bls12_381_limbs_and_dec_eq
#print axioms ZkBilinearCerts.p_bls12_381_bit_bounds
#print axioms ZkBilinearCerts.fp6_381_to_from_simple
#print axioms ZkBilinearCerts.fp6_381_from_to_simple
#print axioms ZkBilinearCerts.bls12_381_fp6_trinomial_isomorphism
#print axioms ZkBilinearCerts.bls12_381_fp6_to_simple_hom
#print axioms ZkBilinearCerts.fp12_381_to_from_simple
#print axioms ZkBilinearCerts.fp12_381_from_to_simple
#print axioms ZkBilinearCerts.bls12_381_fp12_trinomial_isomorphism
#print axioms ZkBilinearCerts.bls12_381_fp12_to_simple_hom
#print axioms ZkBilinearCerts.odd_bezout_two_pow
#print axioms ZkBilinearCerts.odd_nat_coprime_two_pow
#print axioms ZkBilinearCerts.crt_uniqueness_of_coprime
#print axioms ZkBilinearCerts.crt_uniqueness_of_odd
#print axioms ZkBilinearCerts.pasta_linear_crt_3x88_and_4x64_sound
#print axioms ZkBilinearCerts.pasta_wrong_field_mul_sound
#print axioms ZkBilinearCerts.bls12_381_crt30_carry_slack_sound
#print axioms ZkBilinearCerts.bls12_381_crt30_mul_sound
#print axioms ZkBilinearCerts.bls12_381_crt30_out_reconstruction_sound
