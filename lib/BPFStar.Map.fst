(* BPFStar.Map -- implementation.

   All map operations are axiomatised (admit) since they are
   opaque BPF VM operations. The real implementations come from
   the BPF helper functions at runtime. *)
module BPFStar.Map

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

(* Concrete definitions for abstract types. These are
   placeholders -- the extraction maps them to the real
   BPF map structures. *)
let bpf_map _ _ = unit
let map_perm #_ #_ _ = emp
let map_value #_ #_ _ _ _ = emp

let bpf_map_lookup_elem #_ #_ _ _ = admit ()
let bpf_map_update_elem #_ #_ _ _ _ _ = admit ()
let bpf_map_delete_elem #_ #_ _ _ = admit ()
let release_map_value #_ #_ _ _ #_ = admit ()
let read_map_value #_ #_ _ _ #_ = admit ()
let write_map_value #_ #_ _ _ _ #_ = admit ()
