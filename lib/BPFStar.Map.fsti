(* BPFStar.Map -- BPF map types and operations.

   Models BPF maps as abstract resources with separation logic
   permissions. The extraction plugin (ExtractPulseBPF) handles
   the translation to correct BPF C calling conventions. *)
module BPFStar.Map

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

(* Abstract BPF map handle, parametric over key and value types. *)
val bpf_map (kt: Type0) (vt: Type0) : Type0

(* Ownership of a BPF map. *)
val map_perm (#kt #vt: Type0) (m: bpf_map kt vt) : slprop

(* Permission for a borrowed map value pointer. *)
val map_value (#kt #vt: Type0) (m: bpf_map kt vt) (p: ref vt) (v: erased vt) : slprop

(* Look up a key in a BPF map.

   Takes the key by value. The extraction plugin generates
   code that puts the key on the stack and passes its address
   to bpf_map_lookup_elem.

   Returns a nullable pointer -- caller must check is_null. *)
val map_lookup
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: kt)
  : stt (ref vt)
    (requires map_perm m)
    (ensures fun r ->
      map_perm m **
      (if is_null r then emp
       else exists* v. map_value m r v))

(* Release a borrowed map value pointer. No-op at runtime. *)
val release_map_value
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (p: ref vt)
  : stt unit
    (requires exists* v. map_value m p v)
    (ensures fun _ -> emp)

(* Read from a borrowed map value pointer. *)
val read_map_value
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (p: ref vt)
  : stt vt
    (requires exists* v. map_value m p v)
    (ensures fun x -> map_value m p (hide x))

(* Write to a borrowed map value pointer. *)
val write_map_value
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (p: ref vt)
  (x: vt)
  : stt unit
    (requires exists* v. map_value m p v)
    (ensures fun _ -> map_value m p (hide x))

(* Low-level map operations matching BPF C convention.
   These take refs to key/value. Normally use map_lookup instead. *)
val bpf_map_lookup_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: ref kt)
  : stt (ref vt)
    (requires map_perm m ** (exists* kv. pts_to k kv))
    (ensures fun r ->
      map_perm m ** (exists* kv. pts_to k kv) **
      (if is_null r then emp
       else exists* v. map_value m r v))

val bpf_map_update_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: ref kt)
  (v: ref vt)
  (flags: UInt64.t)
  : stt bpf_ret
    (requires map_perm m ** (exists* kv. pts_to k kv) ** (exists* vv. pts_to v vv))
    (ensures fun _ -> map_perm m ** (exists* kv. pts_to k kv) ** (exists* vv. pts_to v vv))

val bpf_map_delete_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: ref kt)
  : stt bpf_ret
    (requires map_perm m ** (exists* kv. pts_to k kv))
    (ensures fun _ -> map_perm m ** (exists* kv. pts_to k kv))
