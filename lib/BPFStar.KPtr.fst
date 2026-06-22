(* BPFStar.KPtr -- implementation.
   Kernel pointers are represented as unit at verification
   time. The extraction plugin handles the C representation. *)
module BPFStar.KPtr

let kptr _ = unit
