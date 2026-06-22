(* BPFStar.Helpers -- BPF helper function specifications.

   Models the kernel-provided BPF helper functions with
   separation logic contracts and programme-type constraints.

   Helpers are grouped by category:
   1. Universal -- available in all programme types
   2. Tracing -- available in tracing-family programmes
   3. Advanced tracing -- fentry/fexit/LSM only
   4. Kprobe-specific
   5. LSM-specific

   Networking and storage helpers are in separate modules:
     BPFStar.Helpers.Net
     BPFStar.Helpers.Storage

   Map and ring buffer operations are in:
     BPFStar.Map
     BPFStar.RingBuf

   All helpers are axiomatised -- the real implementations
   come from bpf_helpers.h at compile time. *)
module BPFStar.Helpers

open Pulse.Lib.Pervasives
module A = Pulse.Lib.Array
open FStar.Ghost
open BPFStar.Types
open BPFStar.ProgType
open BPFStar.KPtr

(* ================================================================
   1. UNIVERSAL HELPERS
   Available in all programme types, no capability constraint.
   ================================================================ *)

(* --- Process/task info --- *)

(* Returns (tgid << 32) | pid.
   Upper 32 bits: userspace PID (kernel TGID).
   Lower 32 bits: kernel PID (userspace TID). *)
val bpf_get_current_pid_tgid: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Returns (gid << 32) | uid. *)
val bpf_get_current_uid_gid: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Copy current task's comm (command name) into buf.
   buf must be at least 16 bytes (TASK_COMM_LEN).
   Returns 0 on success. *)
val bpf_get_current_comm
  (buf: A.array UInt8.t{A.length buf >= 16})
  (size: UInt32.t{UInt32.v size = A.length buf})
  : stt bpf_ret
    (requires exists* v. A.pts_to buf v)
    (ensures fun _ -> exists* v'. A.pts_to buf v')

(* Returns raw pointer to current task_struct as u64. *)
val bpf_get_current_task: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Returns BTF-typed pointer to current task_struct. *)
val bpf_get_current_task_btf: unit
  -> stt (kptr KTask) emp (fun _ -> emp)

(* Get pid/tgid in a specific namespace.
   dev and ino identify the namespace via /proc/self/ns/pid. *)
val bpf_get_ns_current_pid_tgid
  (#t: Type0)
  (dev: UInt64.t)
  (ino: UInt64.t)
  (nsdata: ref t)
  (size: UInt32.t)
  : stt bpf_ret
    (requires exists* v. pts_to nsdata v)
    (ensures fun _ -> exists* v'. pts_to nsdata v')

(* Send a signal to the current task's thread group. *)
val bpf_send_signal
  (sig: UInt32.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Send a signal to the current thread only. *)
val bpf_send_signal_thread
  (sig: UInt32.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Returns the current CPU ID. *)
val bpf_get_smp_processor_id: unit
  -> stt UInt32.t emp (fun _ -> emp)

(* Returns a pseudo-random 32-bit value. *)
val bpf_get_prandom_u32: unit
  -> stt UInt32.t emp (fun _ -> emp)

(* --- Time --- *)

(* Monotonic clock, excludes suspend time (nanoseconds). *)
val bpf_ktime_get_ns: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Monotonic clock, includes suspend time (nanoseconds). *)
val bpf_ktime_get_boot_ns: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* Coarse-grained monotonic clock (nanoseconds). Cheaper. *)
val bpf_ktime_get_coarse_ns: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* TAI (International Atomic Time) wall clock (nanoseconds). *)
val bpf_ktime_get_tai_ns: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* 64-bit jiffies value. *)
val bpf_jiffies64: unit
  -> stt UInt64.t emp (fun _ -> emp)

(* --- Memory access (universal) --- *)

(* Read size bytes from kernel memory at src into dst.
   Returns 0 on success, negative on error. *)
val bpf_probe_read_kernel
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (src: UInt64.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Read size bytes from user memory at src into dst. *)
val bpf_probe_read_user
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (src: UInt64.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Read a NUL-terminated string from kernel memory.
   Returns positive (byte count including NUL) on success,
   negative on error. *)
val bpf_probe_read_kernel_str
  (dst: A.array UInt8.t)
  (size: UInt32.t{UInt32.v size = A.length dst})
  (src: UInt64.t)
  : stt bpf_ret
    (requires exists* v. A.pts_to dst v)
    (ensures fun r -> exists* v'. A.pts_to dst v' **
      pure (is_positive r \/ is_err r))

(* Read a NUL-terminated string from user memory. *)
val bpf_probe_read_user_str
  (dst: A.array UInt8.t)
  (size: UInt32.t{UInt32.v size = A.length dst})
  (src: UInt64.t)
  : stt bpf_ret
    (requires exists* v. A.pts_to dst v)
    (ensures fun r -> exists* v'. A.pts_to dst v' **
      pure (is_positive r \/ is_err r))

(* Copy data from user space (sleepable variant). *)
val bpf_copy_from_user
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (user_ptr: UInt64.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* --- Debug --- *)

(* Print to /sys/kernel/tracing/trace_pipe. *)
val bpf_trace_printk
  (fmt: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* --- Tail calls --- *)

(* Jump into another BPF programme. Does not return on success.
   On failure (invalid index, nesting limit), returns and
   execution continues. *)
val bpf_tail_call
  (ctx: ctx_ptr)
  (prog_array: UInt64.t)
  (index: UInt32.t)
  : stt unit emp (fun _ -> emp)


(* ================================================================
   2. TRACING-FAMILY HELPERS
   Available in: kprobe, tracepoint, raw_tracepoint,
   fentry, fexit, LSM.
   ================================================================ *)

(* Legacy kernel memory read (use bpf_probe_read_kernel instead). *)
val bpf_probe_read
  (#p: prog_type) {| can_trace p |}
  (#t: Type0)
  (dst: ref t)
  (size: UInt32.t)
  (src: UInt64.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to dst v)
    (ensures fun _ -> exists* v'. pts_to dst v')

(* Legacy string read (use bpf_probe_read_kernel_str instead). *)
val bpf_probe_read_str
  (#p: prog_type) {| can_trace p |}
  (dst: A.array UInt8.t)
  (size: UInt32.t{UInt32.v size = A.length dst})
  (src: UInt64.t)
  : stt bpf_ret
    (requires exists* v. A.pts_to dst v)
    (ensures fun r -> exists* v'. A.pts_to dst v' **
      pure (is_positive r \/ is_err r))

(* Write to user space memory. Dangerous -- restricted to
   tracing programmes, requires CAP_SYS_ADMIN. *)
val bpf_probe_write_user
  (#p: prog_type) {| can_trace p |}
  (#t: Type0)
  (dst: UInt64.t)
  (src: ref t)
  (len: UInt32.t)
  (#v: erased t)
  : stt bpf_ret
    (requires pts_to src v)
    (ensures fun _ -> pts_to src v)

(* Get user or kernel stack trace into buffer.
   Returns positive (bytes written) on success, negative on error. *)
val bpf_get_stack
  (#p: prog_type) {| can_trace p |}
  (ctx: ctx_ptr)
  (buf: A.array UInt8.t)
  (size: UInt32.t{UInt32.v size = A.length buf})
  (flags: UInt64.t)
  : stt bpf_ret
    (requires exists* v. A.pts_to buf v)
    (ensures fun r -> exists* v'. A.pts_to buf v' **
      pure (is_positive r \/ is_err r))

(* Walk stack and return its ID (index in stack trace map).
   Returns non-negative ID on success, negative on error. *)
val bpf_get_stackid
  (#p: prog_type) {| can_trace p |}
  (ctx: ctx_ptr)
  (map: UInt64.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Get the cookie value set at programme attachment. *)
val bpf_get_attach_cookie
  (#p: prog_type) {| can_trace p |}
  (ctx: ctx_ptr)
  : stt UInt64.t emp (fun _ -> emp)


(* ================================================================
   3. ADVANCED TRACING HELPERS
   Available in: fentry, fexit, LSM.
   ================================================================ *)

(* Resolve a struct path to a full path string.
   Returns positive (path length) on success, negative on error.
   Only available in sleepable programmes. *)
val bpf_d_path
  (#p: prog_type) {| can_adv_trace p |}
  (path: kptr KPath)
  (buf: A.array UInt8.t)
  (sz: UInt32.t{UInt32.v sz = A.length buf})
  : stt bpf_ret
    (requires exists* v. A.pts_to buf v)
    (ensures fun r -> exists* v'. A.pts_to buf v' **
      pure (is_positive r \/ is_err r))


(* ================================================================
   4. KPROBE + FENTRY/FEXIT HELPERS
   ================================================================ *)

(* Get the instruction pointer of the traced function. *)
val bpf_get_func_ip
  (#p: prog_type) {| can_func_ip p |}
  (ctx: ctx_ptr)
  : stt UInt64.t emp (fun _ -> emp)


(* ================================================================
   5. KPROBE-EXCLUSIVE HELPERS
   ================================================================ *)

(* Override the return value of a probed function.
   Requires CONFIG_BPF_KPROBE_OVERRIDE. *)
val bpf_override_return
  (#p: prog_type) {| can_kprobe p |}
  (regs: kptr KPtRegs)
  (rc: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)


(* ================================================================
   6. LSM-EXCLUSIVE HELPERS
   ================================================================ *)

(* Get the IMA hash of an inode.
   Only available in sleepable LSM hooks. *)
val bpf_ima_inode_hash
  (#p: prog_type) {| can_lsm p |}
  (inode: kptr KInode)
  (dst: A.array UInt8.t)
  (size: UInt32.t{UInt32.v size = A.length dst})
  : stt bpf_ret
    (requires exists* v. A.pts_to dst v)
    (ensures fun _ -> exists* v'. A.pts_to dst v')

(* Get the IMA hash of a file.
   Only available in sleepable LSM hooks. *)
val bpf_ima_file_hash
  (#p: prog_type) {| can_lsm p |}
  (file: kptr KFile)
  (dst: A.array UInt8.t)
  (size: UInt32.t{UInt32.v size = A.length dst})
  : stt bpf_ret
    (requires exists* v. A.pts_to dst v)
    (ensures fun _ -> exists* v'. A.pts_to dst v')
