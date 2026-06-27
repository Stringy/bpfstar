(* BPFStar.Core -- implementation.
   All CO-RE operations are axiomatised. The extraction plugin
   emits BPF_CORE_READ() macro calls. *)
module BPFStar.Core

open Pulse.Lib.Pervasives
open BPFStar.Types
open BPFStar.KPtr

let field _ _ = string
let mk_field #_ #_ name = name

noeq
type core_path_impl =
  | LeafImpl : string -> core_path_impl
  | StepImpl : string -> core_path_impl -> core_path_impl

let core_path _ _ = core_path_impl
let leaf #_ #_ f = LeafImpl f
let step #_ #_ #_ f rest = StepImpl f rest

let core_read #_ #_ _ _ = admit ()
let core_read_into #_ #_ _ _ _ #_ = admit ()
let core_read_str #_ _ _ _ _ = admit ()
let core_field_exists #_ #_ _ = admit ()
