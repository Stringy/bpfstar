(* Minimal -- A minimal BPF programme written in Pulse.

   Demonstrates the core BPFStar workflow:
   1. Get the current PID via a BPF helper
   2. Look up the PID in a hash map
   3. If found, write an event to a ring buffer
   4. Return 0

   Equivalent to a BPF C programme that attaches to
   tp/raw_syscalls/sys_enter, filters by PID, and
   emits timestamp + pid events via a ring buffer. *)
module Minimal
#lang-pulse
open Pulse.Lib.Pervasives
open BPFStar.Types
open BPFStar.Map
open BPFStar.RingBuf
open BPFStar.Helpers
open BPFStar.Program

(* Event structure sent to userspace via ring buffer *)
noeq
type event = {
  timestamp: UInt64.t;
  pid: UInt32.t;
}

(* Assume we have a PID filter map and a ring buffer. *)
assume val pid_filter : bpf_map UInt32.t UInt32.t
assume val events : bpf_ringbuf

(* Size of event struct in bytes -- passed to bpf_ringbuf_reserve *)
let event_size : UInt64.t = 16uL

(* The main BPF programme entry point *)
[@@ bpf_section "tp/raw_syscalls/sys_enter"]
fn trace_sys_enter (key: ref UInt32.t)
  requires map_perm pid_filter ** ringbuf_perm events ** (exists* v. pts_to key v)
  ensures  map_perm pid_filter ** ringbuf_perm events ** (exists* v. pts_to key v)
{
  (* Get current PID -- upper 32 bits of pid_tgid *)
  let pid_tgid = bpf_get_current_pid_tgid ();
  let pid = FStar.Int.Cast.uint64_to_uint32 (FStar.UInt64.shift_right pid_tgid 32ul);

  (* Store the PID in the key ref for map lookup *)
  key := pid;

  (* Look up PID in the filter map -- key is passed by pointer *)
  let found = bpf_map_lookup_elem pid_filter key;

  if is_null found {
    ()
  } else {
    release_map_value pid_filter found;

    (* Reserve space in the ring buffer *)
    let slot = bpf_ringbuf_reserve #event events event_size 0uL;

    if is_null slot {
      ()
    } else {
      let ts = bpf_ktime_get_boot_ns ();
      slot := { timestamp = ts; pid = pid };
      bpf_ringbuf_submit slot 0uL
    }
  }
}
