(* BPFStar.RingBuf -- Ring buffer with linear ownership.

   Models BPF ring buffers using separation logic to enforce
   the reserve/submit/discard protocol:

   1. Reserve space in the ring buffer (may fail -> null)
   2. If non-null, write data into the reserved slot
   3. Submit (data becomes visible to userspace) or discard

   The ringbuf_reservation slprop is linear -- it must be
   consumed on every code path. Pulse's type system prevents
   forgetting to submit or discard. *)
module BPFStar.RingBuf

open Pulse.Lib.Pervasives
open FStar.Ghost

(* Abstract ring buffer handle. Programmes declare ring buffer
   map instances as globals. *)
val bpf_ringbuf : Type0

(* Ring buffer constructor. Creates a ring buffer with the
   specified size in bytes. The extraction plugin emits the
   BTF-style struct definition in a SEC(".maps") section.

   Usage:
     [@@ CSection ".maps"]
     let events : bpf_ringbuf = define_ringbuf (256ul `UInt32.mul` 1024ul)
*)
val define_ringbuf (size: UInt32.t) : bpf_ringbuf

(* Ownership of a ring buffer for performing operations. *)
val ringbuf_perm (rb: bpf_ringbuf) : slprop

(* Linear permission for a reserved ring buffer slot.
   Must be consumed by either submit or discard.
   The ref points to writable memory of type t. *)
val ringbuf_reservation (#t: Type0) (p: ref t) : slprop

(* Reserve space in a ring buffer.

   Returns a pointer to the reserved slot, or null if the
   ring buffer is full. The caller must check is_null before
   use. When non-null, the reservation is a linear resource
   that must be submitted or discarded. *)
(* Reserve space in a ring buffer.

   Takes the ring buffer, the size in bytes to reserve, and
   flags. Returns a pointer to the reserved slot, or null if
   the ring buffer is full. Matches the BPF C convention:
     void *bpf_ringbuf_reserve(void *ringbuf, __u64 size, __u64 flags) *)
val bpf_ringbuf_reserve
  (#t: Type0)
  (rb: bpf_ringbuf)
  (size: FStar.UInt64.t)
  (flags: FStar.UInt64.t)
  : stt (ref t)
    (requires ringbuf_perm rb)
    (ensures fun r ->
      ringbuf_perm rb **
      (if is_null r then emp
       else ringbuf_reservation r ** (exists* v. pts_to r v)))

(* Submit a reserved ring buffer entry.

   The data in the slot becomes visible to userspace consumers.
   Consumes both the reservation and the points-to permission
   -- the programme gives up ownership of the slot. *)
val bpf_ringbuf_submit
  (#t: Type0)
  (p: ref t)
  (flags: FStar.UInt64.t)
  : stt unit
    (requires ringbuf_reservation p ** (exists* v. pts_to p v))
    (ensures fun _ -> emp)

(* Discard a reserved ring buffer entry.

   The slot is freed without sending data to userspace.
   Consumes the reservation -- the programme gives up
   ownership of the slot. *)
val bpf_ringbuf_discard
  (#t: Type0)
  (p: ref t)
  (flags: FStar.UInt64.t)
  : stt unit
    (requires ringbuf_reservation p)
    (ensures fun _ -> emp)
