(* BPFStar.RingBuf -- implementation.

   All ring buffer operations are axiomatised since they are
   opaque BPF VM operations. *)
module BPFStar.RingBuf

open Pulse.Lib.Pervasives
open FStar.Ghost

let bpf_ringbuf = unit

let define_ringbuf _ = admit ()

let ringbuf_perm _ = emp
let ringbuf_reservation #_ _ = emp

let bpf_ringbuf_reserve #_ _ _ _ = admit ()
let bpf_ringbuf_submit #_ _ _ = admit ()
let bpf_ringbuf_discard #_ _ _ = admit ()
