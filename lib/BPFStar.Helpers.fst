(* BPFStar.Helpers -- implementation.
   All helpers are axiomatised since they are opaque BPF VM
   operations. The real implementations come from bpf_helpers.h
   at link time. *)
module BPFStar.Helpers

open Pulse.Lib.Pervasives
module A = Pulse.Lib.Array
open FStar.Ghost
open BPFStar.Types
open BPFStar.ProgType
open BPFStar.KPtr

(* Universal *)
let bpf_get_current_pid_tgid () = admit ()
let bpf_get_current_uid_gid () = admit ()
let bpf_get_current_comm _ _ = admit ()
let bpf_get_current_task () = admit ()
let bpf_get_current_task_btf () = admit ()
let bpf_get_ns_current_pid_tgid #_ _ _ _ _ = admit ()
let bpf_send_signal _ = admit ()
let bpf_send_signal_thread _ = admit ()
let bpf_get_smp_processor_id () = admit ()
let bpf_get_prandom_u32 () = admit ()

let bpf_ktime_get_ns () = admit ()
let bpf_ktime_get_boot_ns () = admit ()
let bpf_ktime_get_coarse_ns () = admit ()
let bpf_ktime_get_tai_ns () = admit ()
let bpf_jiffies64 () = admit ()

let bpf_probe_read_kernel #_ _ _ _ #_ = admit ()
let bpf_probe_read_user #_ _ _ _ #_ = admit ()
let bpf_probe_read_kernel_str _ _ _ = admit ()
let bpf_probe_read_user_str _ _ _ = admit ()
let bpf_copy_from_user #_ _ _ _ #_ = admit ()

let bpf_trace_printk _ = admit ()
let bpf_tail_call _ _ _ = admit ()

(* Tracing family *)
let bpf_probe_read #_ #_ #_ _ _ _ #_ = admit ()
let bpf_probe_read_str #_ #_ _ _ _ = admit ()
let bpf_probe_write_user #_ #_ #_ _ _ _ #_ = admit ()
let bpf_get_stack #_ #_ _ _ _ _ = admit ()
let bpf_get_stackid #_ #_ _ _ _ = admit ()
let bpf_get_attach_cookie #_ #_ _ = admit ()

(* Advanced tracing *)
let bpf_d_path #_ #_ _ _ _ = admit ()

(* Kprobe + fentry/fexit *)
let bpf_get_func_ip #_ #_ _ = admit ()

(* Kprobe only *)
let bpf_override_return #_ #_ _ _ = admit ()

(* LSM only *)
let bpf_ima_inode_hash #_ #_ _ _ _ = admit ()
let bpf_ima_file_hash #_ #_ _ _ _ = admit ()
