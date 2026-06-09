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

(* Assume we have a PID filter map and a ring buffer.
   In a real programme these would be declared as BPF map
   globals and set up by the loader. *)
assume val pid_filter : bpf_map UInt32.t UInt32.t
assume val events : bpf_ringbuf

(* The main BPF programme entry point *)
[@@ bpf_section "tp/raw_syscalls/sys_enter"]
fn trace_sys_enter ()
  requires map_perm pid_filter ** ringbuf_perm events
  ensures  map_perm pid_filter ** ringbuf_perm events
{
  (* Get current PID -- upper 32 bits of pid_tgid *)
  let pid_tgid = bpf_get_current_pid_tgid ();
  let pid = FStar.UInt32.uint_to_t (FStar.UInt64.v pid_tgid / 0x100000000);

  (* Look up PID in the filter map *)
  let found = bpf_map_lookup_elem pid_filter pid;

  match found {
    Some p -> {
      (* PID is in the filter map -- release the borrow
         and write an event to the ring buffer *)
      release_map_value pid_filter p;

      (* Reserve space in the ring buffer *)
      let slot = bpf_ringbuf_reserve #event events 0uL;

      match slot {
        Some e -> {
          (* Write event data *)
          let ts = bpf_ktime_get_boot_ns ();
          e := { timestamp = ts; pid = pid };
          bpf_ringbuf_submit e 0uL
        }
        None -> {
          (* Ring buffer full -- nothing to do *)
          ()
        }
      }
    }
    None -> {
      (* PID not in filter -- nothing to do *)
      ()
    }
  }
}
