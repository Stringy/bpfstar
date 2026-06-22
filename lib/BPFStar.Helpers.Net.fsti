(* BPFStar.Helpers.Net -- Networking BPF helpers.

   XDP and TC helpers for packet manipulation, forwarding,
   and checksum operations.

   Programme-type restrictions:
   - XDP-exclusive: xdp_adjust_head/tail/meta, redirect_map
   - TC-exclusive: skb_store_bytes, skb_change_*, skb_pull_data,
     skb_adjust_room, l3/l4_csum_replace
   - XDP + TC: redirect, fib_lookup, csum_diff
   - TC + socket_filter: skb_load_bytes *)
module BPFStar.Helpers.Net

open Pulse.Lib.Pervasives
module A = Pulse.Lib.Array
open FStar.Ghost
open BPFStar.Types
open BPFStar.ProgType
open BPFStar.KPtr

(* ================================================================
   XDP-EXCLUSIVE HELPERS
   ================================================================ *)

(* Adjust the XDP packet data start pointer.
   delta > 0 shrinks headroom, delta < 0 grows it. *)
val bpf_xdp_adjust_head
  (#p: prog_type) {| can_xdp p |}
  (xdp: kptr KXdpMd)
  (delta: Int32.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Adjust the XDP packet data end pointer. *)
val bpf_xdp_adjust_tail
  (#p: prog_type) {| can_xdp p |}
  (xdp: kptr KXdpMd)
  (delta: Int32.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Adjust the XDP metadata pointer. *)
val bpf_xdp_adjust_meta
  (#p: prog_type) {| can_xdp p |}
  (xdp: kptr KXdpMd)
  (delta: Int32.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Redirect packet via a BPF map (DEVMAP, CPUMAP, etc). *)
val bpf_redirect_map
  (#p: prog_type) {| can_xdp p |}
  (map: UInt64.t)
  (key: UInt64.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)


(* ================================================================
   TC-EXCLUSIVE HELPERS
   ================================================================ *)

(* Store bytes into packet at offset. *)
val bpf_skb_store_bytes
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (offset: UInt32.t)
  (from: A.array UInt8.t)
  (len: UInt32.t{UInt32.v len = A.length from})
  (flags: UInt64.t)
  : stt bpf_ret
    (requires exists* v. A.pts_to from v)
    (ensures fun _ -> exists* v. A.pts_to from v)

(* Change packet protocol (e.g. IPv4 <-> IPv6). *)
val bpf_skb_change_proto
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (proto: UInt16.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Grow packet headroom. *)
val bpf_skb_change_head
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (len: UInt32.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Resize packet (trim or grow tail). *)
val bpf_skb_change_tail
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (len: UInt32.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Pull in non-linear data for direct access. *)
val bpf_skb_pull_data
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (len: UInt32.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Grow or shrink packet room. *)
val bpf_skb_adjust_room
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (len_diff: Int32.t)
  (mode: UInt32.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Incrementally recompute L3 (IP) checksum. *)
val bpf_l3_csum_replace
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (offset: UInt32.t)
  (from: UInt64.t)
  (to_val: UInt64.t)
  (size: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Incrementally recompute L4 (TCP/UDP) checksum. *)
val bpf_l4_csum_replace
  (#p: prog_type) {| can_tc p |}
  (skb: kptr KSkBuff)
  (offset: UInt32.t)
  (from: UInt64.t)
  (to_val: UInt64.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)


(* ================================================================
   XDP + TC HELPERS
   ================================================================ *)

(* Redirect packet to network device. *)
val bpf_redirect
  (#p: prog_type) {| can_net_fwd p |}
  (ifindex: UInt32.t)
  (flags: UInt64.t)
  : stt bpf_ret emp (fun _ -> emp)

(* Perform FIB (forwarding information base) lookup. *)
val bpf_fib_lookup
  (#p: prog_type) {| can_net_fwd p |}
  (#t: Type0)
  (ctx: ctx_ptr)
  (params: ref t)
  (plen: Int32.t)
  (flags: UInt32.t)
  : stt bpf_ret
    (requires exists* v. pts_to params v)
    (ensures fun _ -> exists* v'. pts_to params v')

(* Compute checksum difference. *)
val bpf_csum_diff
  (#p: prog_type) {| can_net_fwd p |}
  (from: A.array UInt32.t)
  (from_size: UInt32.t{UInt32.v from_size = 4 * A.length from})
  (to_arr: A.array UInt32.t)
  (to_size: UInt32.t{UInt32.v to_size = 4 * A.length to_arr})
  (seed: UInt32.t)
  : stt Int64.t
    (requires exists* v1 v2. A.pts_to from v1 ** A.pts_to to_arr v2)
    (ensures fun _ -> exists* v1 v2. A.pts_to from v1 ** A.pts_to to_arr v2)


(* ================================================================
   TC + SOCKET_FILTER HELPERS
   ================================================================ *)

(* Load bytes from packet. *)
val bpf_skb_load_bytes
  (#p: prog_type) {| can_skb_read p |}
  (skb: kptr KSkBuff)
  (offset: UInt32.t)
  (to_buf: A.array UInt8.t)
  (len: UInt32.t{UInt32.v len = A.length to_buf})
  : stt bpf_ret
    (requires exists* v. A.pts_to to_buf v)
    (ensures fun _ -> exists* v'. A.pts_to to_buf v')
