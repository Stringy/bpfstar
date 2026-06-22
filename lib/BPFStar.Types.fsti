(* BPFStar.Types -- Common BPF types and constants.

   Defines the scalar types, return codes, and map flags used
   throughout BPF programmes. These correspond to definitions
   in linux/bpf.h and bpf_helpers.h. *)
module BPFStar.Types

open FStar.UInt32
open FStar.UInt64
open FStar.Int32

(* BPF map update flags *)
let bpf_any      : UInt64.t = 0uL    // create or update
let bpf_noexist  : UInt64.t = 1uL    // create only, fail if exists
let bpf_exist    : UInt64.t = 2uL    // update only, fail if missing

(* Ring buffer flags *)
let bpf_rb_no_wakeup  : UInt64.t = 1uL
let bpf_rb_force_wakeup : UInt64.t = 2uL

(* BPF local storage flags *)
let bpf_local_storage_get_f_create : UInt64.t = 1uL

(* BPF helper return: 0 on success, negative on error.
   Some helpers (probe_read_*_str, d_path, get_stack) return
   positive values on success -- use per-helper postconditions
   rather than is_ok/is_err for those. *)
type bpf_ret = Int32.t

(* Opaque kernel pointer type for BPF programme context arguments.
   Extracts to void* in C. Used as the parameter type for BPF
   programme entry points -- the actual kernel struct type is
   provided by the BPF_PROG wrapper macro. *)
val ctx_ptr : Type0

let bpf_ok : bpf_ret = 0l

(* Predicate for successful BPF helper returns (standard convention) *)
let is_ok (r: bpf_ret) : bool = Int32.v r = 0
let is_err (r: bpf_ret) : bool = Int32.v r < 0

(* Predicate for positive-success returns (str/path/stack helpers) *)
let is_positive (r: bpf_ret) : bool = Int32.v r > 0
