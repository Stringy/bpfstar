(* BPFStar.SpinLock -- BPF spin lock with separation logic.

   Models BPF spin locks using separation logic to enforce
   the lock/unlock protocol:

   1. A lock protects a resource (slprop)
   2. Acquiring the lock gives you the protected resource
   3. Releasing the lock requires giving the resource back

   Pulse's type system prevents:
   - Forgetting to unlock (resource leak)
   - Double-locking (deadlock)
   - Accessing protected data without holding the lock
   - Unlocking without holding the lock

   BPF spin locks have additional kernel restrictions:
   - No nested locking (one lock at a time)
   - Limited critical section size
   - Must release before programme returns
   All of these are naturally enforced by the separation
   logic contract. *)
module BPFStar.SpinLock

open Pulse.Lib.Pervasives
open BPFStar.Types

(* Abstract lock type. The resource parameter R describes
   what the lock protects. *)
val bpf_spin_lock_t : Type0

(* The lock invariant. States that the lock exists and
   protects resource R. This permission is always held
   by the programme -- it represents the lock itself,
   not the locked state. *)
val lock_inv (l: bpf_spin_lock_t) (r: slprop) : slprop

(* Acquire the lock. Consumes lock_inv and produces
   lock_inv ** R. The caller now owns the protected
   resource and can access it. *)
val bpf_spin_lock
  (#r: slprop)
  (l: bpf_spin_lock_t)
  : stt unit
    (requires lock_inv l r)
    (ensures fun _ -> lock_inv l r ** r)

(* Release the lock. Consumes lock_inv ** R. The caller
   gives back the protected resource. *)
val bpf_spin_unlock
  (#r: slprop)
  (l: bpf_spin_lock_t)
  : stt unit
    (requires lock_inv l r ** r)
    (ensures fun _ -> lock_inv l r)
