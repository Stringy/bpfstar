(* BPFStar.Helpers.Storage -- BPF local storage helpers.

   Local storage provides per-object (socket, inode, task, cgroup)
   key-value storage associated with a BPF map. The API is similar
   to map operations but keyed by kernel objects rather than
   user-defined keys.

   get returns a nullable pointer -- caller must check is_null.
   delete is unconditional.

   Programme-type restrictions:
   - inode_storage: LSM only
   - task_storage: universal
   - cgrp_storage: universal
   - sk_storage: TC, cgroup, sock_ops, sk_msg, LSM, fentry, fexit *)
module BPFStar.Helpers.Storage

open Pulse.Lib.Pervasives
open FStar.Ghost
open BPFStar.Types
open BPFStar.ProgType
open BPFStar.KPtr
open BPFStar.Map

(* --- Storage permissions ---
   Analogous to map_perm / map_value for regular maps. *)

val storage_perm (#vt: Type0) (m: bpf_map unit vt) : slprop
val storage_value (#vt: Type0) (m: bpf_map unit vt) (p: ref vt) (v: erased vt) : slprop

val release_storage_value
  (#vt: Type0)
  (m: bpf_map unit vt)
  (p: ref vt)
  : stt unit
    (requires exists* v. storage_value m p v)
    (ensures fun _ -> emp)

val read_storage_value
  (#vt: Type0)
  (m: bpf_map unit vt)
  (p: ref vt)
  : stt vt
    (requires exists* v. storage_value m p v)
    (ensures fun x -> storage_value m p (hide x))

val write_storage_value
  (#vt: Type0)
  (m: bpf_map unit vt)
  (p: ref vt)
  (x: vt)
  : stt unit
    (requires exists* v. storage_value m p v)
    (ensures fun _ -> storage_value m p (hide x))

(* --- Inode storage (LSM only) --- *)

val bpf_inode_storage_get
  (#p: prog_type) {| can_lsm p |}
  (#vt: Type0)
  (m: bpf_map unit vt)
  (inode: kptr KInode)
  (value: ref vt)
  (flags: UInt64.t)
  : stt (ref vt)
    (requires storage_perm m ** (exists* v. pts_to value v))
    (ensures fun r ->
      storage_perm m ** (exists* v. pts_to value v) **
      (if is_null r then emp
       else exists* sv. storage_value m r sv))

val bpf_inode_storage_delete
  (#p: prog_type) {| can_lsm p |}
  (#vt: Type0)
  (m: bpf_map unit vt)
  (inode: kptr KInode)
  : stt bpf_ret
    (requires storage_perm m)
    (ensures fun _ -> storage_perm m)

(* --- Task storage (universal) --- *)

val bpf_task_storage_get
  (#vt: Type0)
  (m: bpf_map unit vt)
  (task: kptr KTask)
  (value: ref vt)
  (flags: UInt64.t)
  : stt (ref vt)
    (requires storage_perm m ** (exists* v. pts_to value v))
    (ensures fun r ->
      storage_perm m ** (exists* v. pts_to value v) **
      (if is_null r then emp
       else exists* sv. storage_value m r sv))

val bpf_task_storage_delete
  (#vt: Type0)
  (m: bpf_map unit vt)
  (task: kptr KTask)
  : stt bpf_ret
    (requires storage_perm m)
    (ensures fun _ -> storage_perm m)

(* --- Cgroup storage (universal) --- *)

val bpf_cgrp_storage_get
  (#vt: Type0)
  (m: bpf_map unit vt)
  (cgroup: kptr KCgroup)
  (value: ref vt)
  (flags: UInt64.t)
  : stt (ref vt)
    (requires storage_perm m ** (exists* v. pts_to value v))
    (ensures fun r ->
      storage_perm m ** (exists* v. pts_to value v) **
      (if is_null r then emp
       else exists* sv. storage_value m r sv))

val bpf_cgrp_storage_delete
  (#vt: Type0)
  (m: bpf_map unit vt)
  (cgroup: kptr KCgroup)
  : stt bpf_ret
    (requires storage_perm m)
    (ensures fun _ -> storage_perm m)

(* --- Socket storage (restricted) --- *)

val bpf_sk_storage_get
  (#p: prog_type) {| can_sk_storage p |}
  (#vt: Type0)
  (m: bpf_map unit vt)
  (sk: kptr KSocket)
  (value: ref vt)
  (flags: UInt64.t)
  : stt (ref vt)
    (requires storage_perm m ** (exists* v. pts_to value v))
    (ensures fun r ->
      storage_perm m ** (exists* v. pts_to value v) **
      (if is_null r then emp
       else exists* sv. storage_value m r sv))

val bpf_sk_storage_delete
  (#p: prog_type) {| can_sk_storage p |}
  (#vt: Type0)
  (m: bpf_map unit vt)
  (sk: kptr KSocket)
  : stt bpf_ret
    (requires storage_perm m)
    (ensures fun _ -> storage_perm m)
