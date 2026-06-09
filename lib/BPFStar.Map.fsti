(* BPFStar.Map -- BPF map types and operations.

   Models BPF maps as abstract resources with separation logic
   permissions. The API mirrors the BPF C calling convention:
   - lookup takes a pointer to the key and returns a nullable
     pointer to the value
   - update takes pointers to key and value
   - delete takes a pointer to the key

   This ensures extraction produces correct BPF C without any
   post-processing. *)
module BPFStar.Map

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

(* Abstract BPF map handle, parametric over key and value types.
   Programmes declare map instances as globals. *)
val bpf_map (kt: Type0) (vt: Type0) : Type0

(* Ownership of a BPF map. *)
val map_perm (#kt #vt: Type0) (m: bpf_map kt vt) : slprop

(* Permission for a borrowed map value pointer. Returned by
   lookup when the result is non-null. *)
val map_value (#kt #vt: Type0) (m: bpf_map kt vt) (p: ref vt) (v: erased vt) : slprop

(* Look up a key in a BPF map.

   Takes a pointer to the key (matching the BPF C convention).
   Returns a pointer to the value, or null if not found.
   The caller must check is_null before dereferencing. *)
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

(* Update or insert a key-value pair in a BPF map.

   Takes pointers to key and value (matching BPF C convention).
   Returns 0 on success, negative on error. *)
val bpf_map_update_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: ref kt)
  (v: ref vt)
  (flags: UInt64.t)
  : stt bpf_ret
    (requires map_perm m ** (exists* kv. pts_to k kv) ** (exists* vv. pts_to v vv))
    (ensures fun _ -> map_perm m ** (exists* kv. pts_to k kv) ** (exists* vv. pts_to v vv))

(* Delete a key from a BPF map.

   Takes a pointer to the key (matching BPF C convention).
   Returns 0 on success, negative on error. *)
val bpf_map_delete_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: ref kt)
  : stt bpf_ret
    (requires map_perm m ** (exists* kv. pts_to k kv))
    (ensures fun _ -> map_perm m ** (exists* kv. pts_to k kv))

(* Convenience wrapper: look up by value.

   Takes the key by value, allocates it on the stack, and
   calls bpf_map_lookup_elem. Extracts to:
     kt __key = k;
     vt *result = bpf_map_lookup_elem(map, &__key);
   which is the idiomatic BPF C pattern. *)
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

(* Release a borrowed map value pointer. *)
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
