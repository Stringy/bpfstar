(* BPFStar.Helpers -- BPF helper function specifications.

   Models the kernel-provided BPF helper functions with
   separation logic contracts. Helpers are grouped by category:

   1. Pure queries -- return information, no state change
   2. Memory readers -- read kernel/user memory into a buffer
   3. Map and ring buffer operations -- in BPFStar.Map and
      BPFStar.RingBuf respectively

   All helpers are axiomatised -- the real implementations
   come from bpf_helpers.h at compile time. *)
module BPFStar.Helpers

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types

(* --- Pure queries ---
   These helpers return scalar values and have no effect
   on programme state. *)

(* Returns (tgid << 32) | pid.
   Upper 32 bits: userspace PID (kernel TGID)
   Lower 32 bits: kernel PID (userspace TID) *)
val bpf_get_current_pid_tgid: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Returns (gid << 32) | uid. *)
val bpf_get_current_uid_gid: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Returns monotonic boot-time timestamp in nanoseconds.
   Includes time spent in suspend. *)
val bpf_ktime_get_boot_ns: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Returns the current CPU ID. *)
val bpf_get_smp_processor_id: unit
  -> stt UInt32.t emp (fun _ -> emp)

(* Returns a pseudo-random 32-bit value. *)
val bpf_get_prandom_u32: unit
  -> stt UInt32.t emp (fun _ -> emp)

(* --- Memory readers ---
   These helpers read memory from kernel or user space
   into a caller-owned buffer. *)

(* Read size bytes from kernel memory at src into dst.
   Returns 0 on success, negative on error.
   dst must be a valid pointer with enough space. *)
val bpf_probe_read_kernel
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (src: UInt64.t)   // raw kernel pointer as u64
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Read size bytes from user memory at src into dst.
   Returns 0 on success, negative on error. *)
val bpf_probe_read_user
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (src: UInt64.t)   // raw user pointer as u64
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Read a null-terminated string from kernel memory.
   Returns number of bytes read (including NUL) on success,
   negative on error. *)
val bpf_probe_read_kernel_str
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (src: UInt64.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Copy current task's comm (command name) into buf.
   buf must be at least 16 bytes (TASK_COMM_LEN).
   Returns 0 on success. *)
val bpf_get_current_comm
  (#t: Type0)
  (buf: ref t)
  (size: UInt32.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to buf v)
    (ensures fun _ -> exists* v'. pts_to buf v')

(* --- Debug ---
   Available in debug builds, compiled out in production. *)

(* Print a formatted message to /sys/kernel/tracing/trace_pipe.
   Uses the BPF instruction-limited format string. *)
val bpf_printk
  (fmt: UInt64.t)  // pointer to format string
  : stt bpf_ret emp (fun _ -> emp)
