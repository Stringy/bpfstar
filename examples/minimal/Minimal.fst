(* Minimal -- A minimal BPF programme written in Pulse.

   Demonstrates the core BPFStar workflow:
   1. Get the current PID via a BPF helper
   2. Look up the PID in a hash map
   3. If found, write an event to a ring buffer

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

(* Size of event struct in bytes *)
let event_size : UInt64.t = 16uL

(* The main BPF programme entry point *)
[@@ bpf_section "tp/raw_syscalls/sys_enter"]
fn trace_sys_enter ()
  requires map_perm pid_filter ** ringbuf_perm events
  ensures  map_perm pid_filter ** ringbuf_perm events
{
  (* Get current PID -- upper 32 bits of pid_tgid *)
  let pid_tgid = bpf_get_current_pid_tgid ();
  let pid = FStar.Int.Cast.uint64_to_uint32 (FStar.UInt64.shift_right pid_tgid 32ul);

  (* Look up PID in the filter map -- key passed by value,
     map_lookup handles the stack allocation internally *)
  let found = map_lookup pid_filter pid;

  if is_null found {
    ()
  } else {
    release_map_value pid_filter found;

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
