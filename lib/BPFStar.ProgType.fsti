(* BPFStar.ProgType -- BPF programme types and capability classes.

   Models which BPF helpers are available in which programme types.
   Each helper category has a capability typeclass; programme types
   register instances for the capabilities they support.

   Universal helpers (maps, ring buffers, time, basic process info)
   need no capability constraint. Restricted helpers (networking,
   LSM-specific, tracing-specific) require the appropriate capability.

   Capability assignments are based on the Linux kernel's
   bpf_func_proto dispatch chains (kernel/bpf/helpers.c,
   net/core/filter.c, kernel/trace/bpf_trace.c, etc). *)
module BPFStar.ProgType

(* --- Programme types --- *)

type prog_type =
  | Kprobe
  | Tracepoint
  | RawTracepoint
  | Fentry
  | Fexit
  | LSM
  | XDP
  | TC
  | CgroupSock
  | SocketFilter
  | SockOps
  | SkMsg

(* --- Capability classes ---

   Each class represents a group of helpers with identical
   programme-type availability. Helpers declare which capability
   they require; programme entry points provide the instance. *)

(* Tracing family: kprobe, tracepoint, raw_tracepoint,
   fentry, fexit, LSM.
   Covers: bpf_probe_read (legacy), bpf_probe_write_user,
   bpf_get_stack, bpf_get_stackid, bpf_get_attach_cookie. *)
class can_trace (p: prog_type) = { _ct: unit }

(* Advanced tracing: fentry, fexit, LSM.
   Covers: bpf_d_path. *)
class can_adv_trace (p: prog_type) = { _cat: unit }

(* Function IP access: kprobe, fentry, fexit.
   Covers: bpf_get_func_ip. *)
class can_func_ip (p: prog_type) = { _cf: unit }

(* LSM-exclusive helpers.
   Covers: bpf_inode_storage_get/delete,
   bpf_ima_inode_hash, bpf_ima_file_hash. *)
class can_lsm (p: prog_type) = { _cl: unit }

(* Kprobe-exclusive helpers.
   Covers: bpf_override_return. *)
class can_kprobe (p: prog_type) = { _ck: unit }

(* Socket storage access: TC, cgroup, sock_ops, sk_msg,
   LSM, fentry, fexit.
   Covers: bpf_sk_storage_get/delete. *)
class can_sk_storage (p: prog_type) = { _cs: unit }

(* XDP-exclusive helpers.
   Covers: bpf_xdp_adjust_head/tail/meta,
   bpf_redirect_map. *)
class can_xdp (p: prog_type) = { _cx: unit }

(* TC-exclusive helpers.
   Covers: bpf_skb_store_bytes, bpf_skb_change_proto/head/tail,
   bpf_skb_pull_data, bpf_skb_adjust_room,
   bpf_l3_csum_replace, bpf_l4_csum_replace. *)
class can_tc (p: prog_type) = { _ctc: unit }

(* Network forwarding: XDP + TC.
   Covers: bpf_redirect, bpf_fib_lookup, bpf_csum_diff. *)
class can_net_fwd (p: prog_type) = { _cn: unit }

(* SKB read access: TC + socket_filter.
   Covers: bpf_skb_load_bytes. *)
class can_skb_read (p: prog_type) = { _csr: unit }
