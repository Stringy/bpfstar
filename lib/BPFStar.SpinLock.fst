(* BPFStar.SpinLock -- implementation.
   Lock operations are axiomatised. *)
module BPFStar.SpinLock

open Pulse.Lib.Pervasives
open BPFStar.Types

let bpf_spin_lock_t = unit

let lock_inv _ _ = emp

let bpf_spin_lock #_ _ = admit ()
let bpf_spin_unlock #_ _ = admit ()
