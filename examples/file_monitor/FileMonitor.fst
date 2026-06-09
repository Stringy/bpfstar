(* FileMonitor -- Simplified port of stackrox/fact's trace_file_open.

   Demonstrates real-world BPF patterns:
   - LSM hook with multiple map types
   - Overlayfs deduplication via map lookup + update + delete
   - Inode tracking via map operations
   - Ring buffer event submission *)
module FileMonitor
#lang-pulse
open Pulse.Lib.Pervasives
open BPFStar.Types
open BPFStar.Map
open BPFStar.RingBuf
open BPFStar.Helpers
open FStar.Attributes

(* --- Types --- *)

noeq
type inode_key = {
  ino: UInt64.t;
  dev: UInt64.t;
}

let file_activity_open : UInt32.t = 0ul
let file_activity_creation : UInt32.t = 1ul

noeq
type file_event = {
  timestamp: UInt64.t;
  pid: UInt32.t;
  activity_type: UInt32.t;
  ino_nr: UInt64.t;
  dev_nr: UInt64.t;
}

(* --- Map definitions --- *)

[@@ CSection ".maps"]
let inode_map : bpf_map inode_key UInt8.t = define_hash_map 65536ul

[@@ CSection ".maps"]
let overlayfs_dedup : bpf_map UInt64.t UInt8.t = define_lru_hash_map 256ul

[@@ CSection ".maps"]
let rb : bpf_ringbuf = define_ringbuf 8388608ul

let file_event_size : UInt64.t = 40uL

(* --- Helper: check if inode is monitored --- *)

fn is_inode_monitored (key: inode_key)
  requires map_perm inode_map
  returns b: bool
  ensures map_perm inode_map
{
  let found = map_lookup inode_map key;
  if is_null found {
    false
  } else {
    release_map_value inode_map found;
    true
  }
}

(* --- Helper: add inode to tracking --- *)

fn inode_add (key: inode_key)
  requires map_perm inode_map
  ensures map_perm inode_map
{
  let _r = map_update inode_map key 0uy 0uL;
  ()
}

(* --- Helper: submit event --- *)

fn submit_event
    (activity_type: UInt32.t)
    (ino_nr: UInt64.t)
    (dev_nr: UInt64.t)
    (pid: UInt32.t)
  requires ringbuf_perm rb
  ensures ringbuf_perm rb
{
  let e = bpf_ringbuf_reserve #file_event rb file_event_size 0uL;
  if is_null e {
    ()
  } else {
    let ts = bpf_ktime_get_boot_ns ();
    e := {
      timestamp = ts;
      pid = pid;
      activity_type = activity_type;
      ino_nr = ino_nr;
      dev_nr = dev_nr;
    };
    bpf_ringbuf_submit e 0uL
  }
}

(* --- Helper: handle overlayfs dedup ---
   Returns true if the event should be skipped (duplicate). *)

fn check_overlayfs_dedup (is_overlayfs: bool) (pid_tgid: UInt64.t)
  requires map_perm overlayfs_dedup
  returns skip: bool
  ensures map_perm overlayfs_dedup
{
  if is_overlayfs {
    (* This is the overlayfs event -- mark it and don't skip *)
    let _r = map_update overlayfs_dedup pid_tgid 1uy 0uL;
    false
  } else {
    (* Check if we already saw an overlayfs event for this pid *)
    let flag = map_lookup overlayfs_dedup pid_tgid;
    if is_null flag {
      false  (* no overlayfs event seen, don't skip *)
    } else {
      (* Duplicate -- clean up and skip *)
      release_map_value overlayfs_dedup flag;
      let _r = map_delete overlayfs_dedup pid_tgid;
      true
    }
  }
}

(* --- Main programme ---

   BPF programme entry point for the LSM file_open hook.
   The context is a pointer to struct file (opaque here since
   we don't have CO-RE support yet to read kernel struct fields).

   In a real programme, the context would be used with BPF_PROG:
     SEC("lsm/file_open")
     int BPF_PROG(trace_file_open, struct file* file) { ... }

   For now we take the file pointer as a raw u64 and use
   placeholder values for the fields we'd normally read via
   BPF_CORE_READ. A future CO-RE library would provide typed
   accessors. *)

[@@ CSection "lsm/file_open"]
fn trace_file_open
    (file: UInt64.t)   (* opaque struct file * *)
  requires
    map_perm inode_map **
    map_perm overlayfs_dedup **
    ringbuf_perm rb
  returns r: Int32.t
  ensures
    map_perm inode_map **
    map_perm overlayfs_dedup **
    ringbuf_perm rb
{
  let pid_tgid = bpf_get_current_pid_tgid ();
  let pid = FStar.Int.Cast.uint64_to_uint32 (FStar.UInt64.shift_right pid_tgid 32ul);

  (* In a real programme, these would be read from the file struct
     via BPF_CORE_READ. For now, use the file pointer as a proxy
     for the inode number, and 0 for the device. *)
  let ino_nr = file;
  let dev_nr = 0uL;
  let is_creation = false;
  let is_overlayfs = false;

  let event_type = if is_creation { file_activity_creation } else { file_activity_open };

  (* Overlayfs deduplication *)
  let skip = check_overlayfs_dedup is_overlayfs pid_tgid;

  if skip {
    0l
  } else {
    let key : inode_key = { ino = ino_nr; dev = dev_nr };

    let monitored = is_inode_monitored key;

    if not monitored {
      0l
    } else {
      if is_creation {
        inode_add key
      } else {
        ()
      };
      submit_event event_type ino_nr dev_nr pid;
      0l
    }
  }
}
