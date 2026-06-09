(* BPFStar.Map -- implementation.

   Low-level operations are axiomatised (admit) since they are
   opaque BPF VM operations. The convenience wrappers are real
   Pulse functions that extract to C. *)
module BPFStar.Map
#lang-pulse

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

let bpf_map _ _ = unit
let map_perm #_ #_ _ = emp
let map_value #_ #_ _ _ _ = emp

let bpf_map_lookup_elem #_ #_ _ _ = admit ()
let bpf_map_update_elem #_ #_ _ _ _ _ = admit ()
let bpf_map_delete_elem #_ #_ _ _ = admit ()

inline_for_extraction
fn map_lookup
  (#kt #vt: Type0)
  (m: bpf_map kt vt)
  (k: kt)
  requires map_perm m
  returns r: ref vt
  ensures map_perm m **
          (if is_null r then emp
           else exists* v. map_value m r v)
{
  let mut key = k;
  let r = bpf_map_lookup_elem m key;
  r
}

let release_map_value #_ #_ _ _ = admit ()
let read_map_value #_ #_ _ _ = admit ()
let write_map_value #_ #_ _ _ _ = admit ()
