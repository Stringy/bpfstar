(* BPFStar.Map -- implementation.

   All operations are axiomatised. The extraction plugin
   (ExtractPulseBPF) handles translation to BPF C. *)
module BPFStar.Map

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

let bpf_map _ _ = unit

let define_hash_map #_ #_ _ = admit ()
let define_array_map #_ #_ _ = admit ()
let define_lru_hash_map #_ #_ _ = admit ()
let define_percpu_array_map #_ #_ _ = admit ()

let map_perm #_ #_ _ = emp
let map_value #_ #_ _ _ _ = emp

let map_lookup #_ #_ _ _ = admit ()
let map_update #_ #_ _ _ _ _ = admit ()
let map_delete #_ #_ _ _ = admit ()
let release_map_value #_ #_ _ _ = admit ()
let read_map_value #_ #_ _ _ = admit ()
let write_map_value #_ #_ _ _ _ = admit ()

let bpf_map_lookup_elem #_ #_ _ _ = admit ()
let bpf_map_update_elem #_ #_ _ _ _ _ = admit ()
let bpf_map_delete_elem #_ #_ _ _ = admit ()
