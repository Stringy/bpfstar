(* BPFStar.Map -- BPF map types and operations.

   Models BPF maps as abstract resources with separation logic
   permissions. Map lookup returns a nullable pointer -- the caller
   must check for null before dereferencing. This matches the BPF
   C calling convention directly.

   The specifications model the kernel's contract:
   - lookup returns a pointer that may be null
   - a non-null pointer borrows from the map (map_value_perm)
   - update/delete require map ownership
   - map contents are fully symbolic *)
module BPFStar.Map

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

(* Abstract BPF map handle, parametric over key and value types.
   Programmes declare map instances as globals. *)
val bpf_map (kt: Type0) (vt: Type0) : Type0

(* Ownership of a BPF map. Holding this permission means the
   programme has access to the map for operations. *)
val map_perm (#kt #vt: Type0) (m: bpf_map kt vt) : slprop

(* Permission for a borrowed map value pointer. Returned by
   lookup when the result is non-null. Must be consumed (by
   reading/writing the value and then releasing) before the
   map can be used for another operation. *)
val map_value (#kt #vt: Type0) (m: bpf_map kt vt) (p: ref vt) (v: erased vt) : slprop

(* Look up a key in a BPF map.

   Returns a pointer to the value in the map, or null if the
   key is not found. The caller must check is_null before
   dereferencing. When non-null, the caller gets map_value
   permission -- a borrow from the map. *)
val bpf_map_lookup_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: kt)
  : stt (ref vt)
    (requires map_perm m)
    (ensures fun r ->
      map_perm m **
      (if is_null r then emp
       else exists* v. map_value m r v))

(* Update or insert a key-value pair in a BPF map.

   flags controls the behaviour:
   - bpf_any:     create or update
   - bpf_noexist: create only (fail if exists)
   - bpf_exist:   update only (fail if missing)

   Returns 0 on success, negative on error. *)
val bpf_map_update_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: kt)
  (v: vt)
  (flags: UInt64.t)
  : stt bpf_ret
    (requires map_perm m)
    (ensures fun _ -> map_perm m)

(* Delete a key from a BPF map.

   Returns 0 on success, negative on error (e.g. key not found). *)
val bpf_map_delete_elem
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: kt)
  : stt bpf_ret
    (requires map_perm m)
    (ensures fun _ -> map_perm m)

(* Release a borrowed map value pointer.

   After lookup, the caller holds map_value permission. This
   must be released when the caller is done reading/writing
   the value. *)
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
