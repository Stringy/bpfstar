(* Minimal -- A minimal BPF programme written in Pulse.

   Demonstrates the core BPFStar workflow:
   1. Get the current PID via a BPF helper
   2. Look up the PID in a hash map
   3. If found, write an event to a ring buffer

   The extraction plugin (ExtractPulseBPF) handles all
   BPF-specific C code generation. *)
module Minimal
#lang-pulse
open Pulse.Lib.Pervasives
open BPFStar.Types
open BPFStar.Map
open BPFStar.RingBuf
open BPFStar.Helpers
open FStar.Attributes

(* Event structure sent to userspace via ring buffer *)
noeq
type event = {
  timestamp: UInt64.t;
  pid: UInt32.t;
}

(* BPF map definitions -- these extract to SEC(".maps") globals *)
[@@ CSection ".maps"]
let pid_filter : bpf_map UInt32.t UInt32.t = define_hash_map 8192ul

[@@ CSection ".maps"]
let events : bpf_ringbuf = define_ringbuf 262144ul  (* 256 KB *)

(* Size of event struct in bytes *)
let event_size : UInt64.t = 16uL

(* The main BPF programme entry point *)
[@@ CSection "tp/raw_syscalls/sys_enter"]
fn trace_sys_enter ()
  requires map_perm pid_filter ** ringbuf_perm events
  ensures  map_perm pid_filter ** ringbuf_perm events
{
  let pid_tgid = bpf_get_current_pid_tgid ();
  let pid = FStar.Int.Cast.uint64_to_uint32 (FStar.UInt64.shift_right pid_tgid 32ul);

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
