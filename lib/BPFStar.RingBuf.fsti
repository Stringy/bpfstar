(* BPFStar.RingBuf -- Ring buffer with linear ownership.

   Models BPF ring buffers using separation logic to enforce
   the reserve/submit/discard protocol:

   1. Reserve space in the ring buffer (may fail -> option)
   2. Write data into the reserved slot
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

(* Ownership of a ring buffer for performing operations. *)
val ringbuf_perm (rb: bpf_ringbuf) : slprop

(* Linear permission for a reserved ring buffer slot.
   Must be consumed by either submit or discard.
   The ref points to writable memory of type t. *)
val ringbuf_reservation (#t: Type0) (p: ref t) : slprop

(* Reserve space in a ring buffer.

   Returns Some with a pointer to the reserved slot, or None
   if the ring buffer is full. The reservation is a linear
   resource that must be submitted or discarded.

   flags: 0 for default, bpf_rb_no_wakeup to suppress
   userspace notification. *)
val bpf_ringbuf_reserve
  (#t: Type0)
  (rb: bpf_ringbuf)
  (flags: FStar.UInt64.t)
  : stt (option (ref t))
    (requires ringbuf_perm rb)
    (ensures fun r ->
      ringbuf_perm rb **
      (match r with
       | Some p -> ringbuf_reservation p ** (exists* v. pts_to p v)
       | None -> emp))

(* Submit a reserved ring buffer entry.

   The data in the slot becomes visible to userspace consumers.
   Consumes both the reservation and the points-to permission
   -- the programme gives up ownership of the slot. *)
val bpf_ringbuf_submit
  (#t: Type0)
  (p: ref t)
  (#v: erased t)
  (flags: FStar.UInt64.t)
  : stt unit
    (requires ringbuf_reservation p ** pts_to p v)
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

