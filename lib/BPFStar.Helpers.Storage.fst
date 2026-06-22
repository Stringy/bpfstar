(* BPFStar.Helpers.Storage -- implementation.
   All storage operations are axiomatised. *)
module BPFStar.Helpers.Storage

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types
open BPFStar.ProgType
open BPFStar.KPtr
open BPFStar.Map

let storage_perm #_ _ = emp
let storage_value #_ _ _ _ = emp

let release_storage_value #_ _ _ = admit ()
let read_storage_value #_ _ _ = admit ()
let write_storage_value #_ _ _ _ = admit ()

let bpf_inode_storage_get #_ #_ #_ _ _ _ _ = admit ()
let bpf_inode_storage_delete #_ #_ #_ _ _ = admit ()

let bpf_task_storage_get #_ _ _ _ _ = admit ()
let bpf_task_storage_delete #_ _ _ = admit ()

let bpf_cgrp_storage_get #_ _ _ _ _ = admit ()
let bpf_cgrp_storage_delete #_ _ _ = admit ()

let bpf_sk_storage_get #_ #_ #_ _ _ _ _ = admit ()
let bpf_sk_storage_delete #_ #_ #_ _ _ = admit ()
