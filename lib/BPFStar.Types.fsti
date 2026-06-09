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

(* BPF helper return: 0 on success, negative on error *)
type bpf_ret = Int32.t

let bpf_ok : bpf_ret = 0l

(* Predicate for successful BPF helper returns *)
let is_ok (r: bpf_ret) : bool = Int32.v r = 0
let is_err (r: bpf_ret) : bool = Int32.v r < 0
