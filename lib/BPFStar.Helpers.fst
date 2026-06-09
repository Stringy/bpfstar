(* BPFStar.Helpers -- implementation.

   All helpers are axiomatised since they are opaque BPF VM
   operations. The real implementations come from bpf_helpers.h
   at link time. *)
module BPFStar.Helpers

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

let bpf_get_current_pid_tgid () = admit ()
let bpf_get_current_uid_gid () = admit ()
let bpf_ktime_get_boot_ns () = admit ()
let bpf_get_smp_processor_id () = admit ()
let bpf_get_prandom_u32 () = admit ()

let bpf_probe_read_kernel #_ _ _ _ #_ = admit ()
let bpf_probe_read_user #_ _ _ _ #_ = admit ()
let bpf_probe_read_kernel_str #_ _ _ _ #_ = admit ()
let bpf_get_current_comm #_ _ _ #_ = admit ()

let bpf_printk _ = admit ()
