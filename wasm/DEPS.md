# Dependencies from `ring` crate

Below follows a list of symbols misisng for each subset of functionality exposed
in the DIDKit API from the `ring` crate for the WASM target.

These functions are independent:
- `get_version`
- `key_to_did`
- `key_to_verification_method`

Here are relevant links about these issues:
- [https://github.com/briansmith/ring/issues/918]()
- [https://github.com/briansmith/ring/pull/992/files]()
- [https://github.com/briansmith/ring/pull/996/files]()

The current implemented symbols in the linked PRs are hidden behind a feature
gate on the crate. See [spruceid/ssi](https://github.com/spruceid/didkit/tree/wasm)

## All

Included functions:

- `generate_ed25519_key`
- `issue_credential`
- `verify_credential`
- `issue_presentation`
- `verify_presentation`

Missing symbols:

```
  (import "env" "GFp_bn_from_montgomery_in_place" (func $GFp_bn_from_montgomery_in_place (type $t18)))
  (import "env" "GFp_bn_neg_inv_mod_r_u64" (func $GFp_bn_neg_inv_mod_r_u64 (type $t38)))
  (import "env" "GFp_limbs_mul_add_limb" (func $GFp_limbs_mul_add_limb (type $t12)))
  (import "env" "GFp_memcmp" (func $GFp_memcmp (type $t9)))
  (import "env" "GFp_nistz256_add" (func $GFp_nistz256_add (type $t8)))
  (import "env" "GFp_nistz256_mul_mont" (func $GFp_nistz256_mul_mont (type $t8)))
  (import "env" "GFp_nistz256_point_add" (func $GFp_nistz256_point_add (type $t8)))
  (import "env" "GFp_nistz256_point_mul" (func $GFp_nistz256_point_mul (type $t11)))
  (import "env" "GFp_nistz256_sqr_mont" (func $GFp_nistz256_sqr_mont (type $t5)))
  (import "env" "GFp_nistz384_point_add" (func $GFp_nistz384_point_add (type $t8)))
  (import "env" "GFp_nistz384_point_mul" (func $GFp_nistz384_point_mul (type $t11)))
  (import "env" "GFp_p256_scalar_mul_mont" (func $GFp_p256_scalar_mul_mont (type $t8)))
  (import "env" "GFp_p256_scalar_sqr_mont" (func $GFp_p256_scalar_sqr_mont (type $t5)))
  (import "env" "GFp_p256_scalar_sqr_rep_mont" (func $GFp_p256_scalar_sqr_rep_mont (type $t8)))
  (import "env" "GFp_p384_elem_add" (func $GFp_p384_elem_add (type $t8)))
  (import "env" "GFp_p384_elem_mul_mont" (func $GFp_p384_elem_mul_mont (type $t8)))
  (import "env" "GFp_p384_scalar_mul_mont" (func $GFp_p384_scalar_mul_mont (type $t8)))
  (import "env" "GFp_x25519_fe_invert" (func $GFp_x25519_fe_invert (type $t5)))
  (import "env" "GFp_x25519_fe_isnegative" (func $GFp_x25519_fe_isnegative (type $t3)))
  (import "env" "GFp_x25519_fe_mul_ttt" (func $GFp_x25519_fe_mul_ttt (type $t8)))
  (import "env" "GFp_x25519_fe_neg" (func $GFp_x25519_fe_neg (type $t2)))
  (import "env" "GFp_x25519_fe_tobytes" (func $GFp_x25519_fe_tobytes (type $t5)))
  (import "env" "GFp_x25519_ge_double_scalarmult_vartime" (func $GFp_x25519_ge_double_scalarmult_vartime (type $t11)))
  (import "env" "GFp_x25519_ge_frombytes_vartime" (func $GFp_x25519_ge_frombytes_vartime (type $t6)))
  (import "env" "GFp_x25519_ge_scalarmult_base" (func $GFp_x25519_ge_scalarmult_base (type $t5)))
  (import "env" "GFp_x25519_sc_mask" (func $GFp_x25519_sc_mask (type $t2)))
  (import "env" "GFp_x25519_sc_muladd" (func $GFp_x25519_sc_muladd (type $t11)))
  (import "env" "GFp_x25519_sc_reduce" (func $GFp_x25519_sc_reduce (type $t2)))
```

## Generate

Included functions:

- `generate_ed25519_key`

Missing symbols:

```
  (import "env" "GFp_x25519_fe_invert" (func $GFp_x25519_fe_invert (type $t5)))
  (import "env" "GFp_x25519_fe_isnegative" (func $GFp_x25519_fe_isnegative (type $t3)))
  (import "env" "GFp_x25519_fe_mul_ttt" (func $GFp_x25519_fe_mul_ttt (type $t7)))
  (import "env" "GFp_x25519_fe_tobytes" (func $GFp_x25519_fe_tobytes (type $t5)))
  (import "env" "GFp_x25519_ge_scalarmult_base" (func $GFp_x25519_ge_scalarmult_base (type $t5)))
  (import "env" "GFp_x25519_sc_mask" (func $GFp_x25519_sc_mask (type $t2)))
```

## Issue

Included functions:

- `issue_credential`
- `issue_presentation`

Missing symbols:

```
  (import "env" "GFp_nistz256_add" (func $GFp_nistz256_add (type $t8)))
  (import "env" "GFp_nistz256_mul_mont" (func $GFp_nistz256_mul_mont (type $t8)))
  (import "env" "GFp_nistz256_point_add" (func $GFp_nistz256_point_add (type $t8)))
  (import "env" "GFp_nistz256_point_mul" (func $GFp_nistz256_point_mul (type $t10)))
  (import "env" "GFp_nistz256_sqr_mont" (func $GFp_nistz256_sqr_mont (type $t5)))
  (import "env" "GFp_nistz384_point_add" (func $GFp_nistz384_point_add (type $t8)))
  (import "env" "GFp_nistz384_point_mul" (func $GFp_nistz384_point_mul (type $t10)))
  (import "env" "GFp_p256_scalar_mul_mont" (func $GFp_p256_scalar_mul_mont (type $t8)))
  (import "env" "GFp_p256_scalar_sqr_mont" (func $GFp_p256_scalar_sqr_mont (type $t5)))
  (import "env" "GFp_p256_scalar_sqr_rep_mont" (func $GFp_p256_scalar_sqr_rep_mont (type $t8)))
  (import "env" "GFp_p384_elem_add" (func $GFp_p384_elem_add (type $t8)))
  (import "env" "GFp_p384_elem_mul_mont" (func $GFp_p384_elem_mul_mont (type $t8)))
  (import "env" "GFp_p384_scalar_mul_mont" (func $GFp_p384_scalar_mul_mont (type $t8)))
  (import "env" "GFp_x25519_fe_invert" (func $GFp_x25519_fe_invert (type $t5)))
  (import "env" "GFp_x25519_fe_isnegative" (func $GFp_x25519_fe_isnegative (type $t3)))
  (import "env" "GFp_x25519_fe_mul_ttt" (func $GFp_x25519_fe_mul_ttt (type $t8)))
  (import "env" "GFp_x25519_fe_tobytes" (func $GFp_x25519_fe_tobytes (type $t5)))
  (import "env" "GFp_x25519_ge_scalarmult_base" (func $GFp_x25519_ge_scalarmult_base (type $t5)))
  (import "env" "GFp_x25519_sc_mask" (func $GFp_x25519_sc_mask (type $t2)))
  (import "env" "GFp_x25519_sc_muladd" (func $GFp_x25519_sc_muladd (type $t10)))
  (import "env" "GFp_x25519_sc_reduce" (func $GFp_x25519_sc_reduce (type $t2)))
```

## Verify

Included functions:

- `verify_credential`
- `verify_presentation`

Missing symbols:

```
  (import "env" "GFp_nistz256_add" (func $GFp_nistz256_add (type $t8)))
  (import "env" "GFp_nistz256_mul_mont" (func $GFp_nistz256_mul_mont (type $t8)))
  (import "env" "GFp_nistz256_point_add" (func $GFp_nistz256_point_add (type $t8)))
  (import "env" "GFp_nistz256_point_mul" (func $GFp_nistz256_point_mul (type $t11)))
  (import "env" "GFp_nistz256_sqr_mont" (func $GFp_nistz256_sqr_mont (type $t5)))
  (import "env" "GFp_nistz384_point_add" (func $GFp_nistz384_point_add (type $t8)))
  (import "env" "GFp_nistz384_point_mul" (func $GFp_nistz384_point_mul (type $t11)))
  (import "env" "GFp_p256_scalar_mul_mont" (func $GFp_p256_scalar_mul_mont (type $t8)))
  (import "env" "GFp_p256_scalar_sqr_mont" (func $GFp_p256_scalar_sqr_mont (type $t5)))
  (import "env" "GFp_p256_scalar_sqr_rep_mont" (func $GFp_p256_scalar_sqr_rep_mont (type $t8)))
  (import "env" "GFp_p384_elem_add" (func $GFp_p384_elem_add (type $t8)))
  (import "env" "GFp_p384_elem_mul_mont" (func $GFp_p384_elem_mul_mont (type $t8)))
  (import "env" "GFp_p384_scalar_mul_mont" (func $GFp_p384_scalar_mul_mont (type $t8)))
  (import "env" "GFp_x25519_fe_invert" (func $GFp_x25519_fe_invert (type $t5)))
  (import "env" "GFp_x25519_fe_isnegative" (func $GFp_x25519_fe_isnegative (type $t3)))
  (import "env" "GFp_x25519_fe_mul_ttt" (func $GFp_x25519_fe_mul_ttt (type $t8)))
  (import "env" "GFp_x25519_fe_neg" (func $GFp_x25519_fe_neg (type $t2)))
  (import "env" "GFp_x25519_fe_tobytes" (func $GFp_x25519_fe_tobytes (type $t5)))
  (import "env" "GFp_x25519_ge_double_scalarmult_vartime" (func $GFp_x25519_ge_double_scalarmult_vartime (type $t11)))
  (import "env" "GFp_x25519_ge_frombytes_vartime" (func $GFp_x25519_ge_frombytes_vartime (type $t6)))
  (import "env" "GFp_x25519_ge_scalarmult_base" (func $GFp_x25519_ge_scalarmult_base (type $t5)))
  (import "env" "GFp_x25519_sc_mask" (func $GFp_x25519_sc_mask (type $t2)))
  (import "env" "GFp_x25519_sc_muladd" (func $GFp_x25519_sc_muladd (type $t11)))
  (import "env" "GFp_x25519_sc_reduce" (func $GFp_x25519_sc_reduce (type $t2)))
```

## Credential

Included functions:

- `issue_credential`
- `verify_credential`

Missing symbols:

```
  (import "env" "GFp_nistz256_add" (func $GFp_nistz256_add (type $t8)))
  (import "env" "GFp_nistz256_mul_mont" (func $GFp_nistz256_mul_mont (type $t8)))
  (import "env" "GFp_nistz256_point_add" (func $GFp_nistz256_point_add (type $t8)))
  (import "env" "GFp_nistz256_point_mul" (func $GFp_nistz256_point_mul (type $t11)))
  (import "env" "GFp_nistz256_sqr_mont" (func $GFp_nistz256_sqr_mont (type $t5)))
  (import "env" "GFp_nistz384_point_add" (func $GFp_nistz384_point_add (type $t8)))
  (import "env" "GFp_nistz384_point_mul" (func $GFp_nistz384_point_mul (type $t11)))
  (import "env" "GFp_p256_scalar_mul_mont" (func $GFp_p256_scalar_mul_mont (type $t8)))
  (import "env" "GFp_p256_scalar_sqr_mont" (func $GFp_p256_scalar_sqr_mont (type $t5)))
  (import "env" "GFp_p256_scalar_sqr_rep_mont" (func $GFp_p256_scalar_sqr_rep_mont (type $t8)))
  (import "env" "GFp_p384_elem_add" (func $GFp_p384_elem_add (type $t8)))
  (import "env" "GFp_p384_elem_mul_mont" (func $GFp_p384_elem_mul_mont (type $t8)))
  (import "env" "GFp_p384_scalar_mul_mont" (func $GFp_p384_scalar_mul_mont (type $t8)))
  (import "env" "GFp_x25519_fe_invert" (func $GFp_x25519_fe_invert (type $t5)))
  (import "env" "GFp_x25519_fe_isnegative" (func $GFp_x25519_fe_isnegative (type $t3)))
  (import "env" "GFp_x25519_fe_mul_ttt" (func $GFp_x25519_fe_mul_ttt (type $t8)))
  (import "env" "GFp_x25519_fe_neg" (func $GFp_x25519_fe_neg (type $t2)))
  (import "env" "GFp_x25519_fe_tobytes" (func $GFp_x25519_fe_tobytes (type $t5)))
  (import "env" "GFp_x25519_ge_double_scalarmult_vartime" (func $GFp_x25519_ge_double_scalarmult_vartime (type $t11)))
  (import "env" "GFp_x25519_ge_frombytes_vartime" (func $GFp_x25519_ge_frombytes_vartime (type $t6)))
  (import "env" "GFp_x25519_ge_scalarmult_base" (func $GFp_x25519_ge_scalarmult_base (type $t5)))
  (import "env" "GFp_x25519_sc_mask" (func $GFp_x25519_sc_mask (type $t2)))
  (import "env" "GFp_x25519_sc_muladd" (func $GFp_x25519_sc_muladd (type $t11)))
  (import "env" "GFp_x25519_sc_reduce" (func $GFp_x25519_sc_reduce (type $t2)))
```

## Presentation

Included functions:

- `issue_presentation`
- `verify_presentation`

Missing symbols:

```
  (import "env" "GFp_nistz256_add" (func $GFp_nistz256_add (type $t8)))
  (import "env" "GFp_nistz256_mul_mont" (func $GFp_nistz256_mul_mont (type $t8)))
  (import "env" "GFp_nistz256_point_add" (func $GFp_nistz256_point_add (type $t8)))
  (import "env" "GFp_nistz256_point_mul" (func $GFp_nistz256_point_mul (type $t11)))
  (import "env" "GFp_nistz256_sqr_mont" (func $GFp_nistz256_sqr_mont (type $t5)))
  (import "env" "GFp_nistz384_point_add" (func $GFp_nistz384_point_add (type $t8)))
  (import "env" "GFp_nistz384_point_mul" (func $GFp_nistz384_point_mul (type $t11)))
  (import "env" "GFp_p256_scalar_mul_mont" (func $GFp_p256_scalar_mul_mont (type $t8)))
  (import "env" "GFp_p256_scalar_sqr_mont" (func $GFp_p256_scalar_sqr_mont (type $t5)))
  (import "env" "GFp_p256_scalar_sqr_rep_mont" (func $GFp_p256_scalar_sqr_rep_mont (type $t8)))
  (import "env" "GFp_p384_elem_add" (func $GFp_p384_elem_add (type $t8)))
  (import "env" "GFp_p384_elem_mul_mont" (func $GFp_p384_elem_mul_mont (type $t8)))
  (import "env" "GFp_p384_scalar_mul_mont" (func $GFp_p384_scalar_mul_mont (type $t8)))
  (import "env" "GFp_x25519_fe_invert" (func $GFp_x25519_fe_invert (type $t5)))
  (import "env" "GFp_x25519_fe_isnegative" (func $GFp_x25519_fe_isnegative (type $t3)))
  (import "env" "GFp_x25519_fe_mul_ttt" (func $GFp_x25519_fe_mul_ttt (type $t8)))
  (import "env" "GFp_x25519_fe_neg" (func $GFp_x25519_fe_neg (type $t2)))
  (import "env" "GFp_x25519_fe_tobytes" (func $GFp_x25519_fe_tobytes (type $t5)))
  (import "env" "GFp_x25519_ge_double_scalarmult_vartime" (func $GFp_x25519_ge_double_scalarmult_vartime (type $t11)))
  (import "env" "GFp_x25519_ge_frombytes_vartime" (func $GFp_x25519_ge_frombytes_vartime (type $t6)))
  (import "env" "GFp_x25519_ge_scalarmult_base" (func $GFp_x25519_ge_scalarmult_base (type $t5)))
  (import "env" "GFp_x25519_sc_mask" (func $GFp_x25519_sc_mask (type $t2)))
  (import "env" "GFp_x25519_sc_muladd" (func $GFp_x25519_sc_muladd (type $t11)))
  (import "env" "GFp_x25519_sc_reduce" (func $GFp_x25519_sc_reduce (type $t2)))
```
