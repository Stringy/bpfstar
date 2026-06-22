(* BPFStar.Helpers.Net -- implementation.
   All networking operations are axiomatised. *)
module BPFStar.Helpers.Net

open Pulse.Lib.Pervasives
module A = Pulse.Lib.Array
open FStar.Ghost
open BPFStar.Types
open BPFStar.ProgType
open BPFStar.KPtr

(* XDP *)
let bpf_xdp_adjust_head #_ #_ _ _ = admit ()
let bpf_xdp_adjust_tail #_ #_ _ _ = admit ()
let bpf_xdp_adjust_meta #_ #_ _ _ = admit ()
let bpf_redirect_map #_ #_ _ _ _ = admit ()

(* TC *)
let bpf_skb_store_bytes #_ #_ _ _ _ _ _ = admit ()
let bpf_skb_change_proto #_ #_ _ _ _ = admit ()
let bpf_skb_change_head #_ #_ _ _ _ = admit ()
let bpf_skb_change_tail #_ #_ _ _ _ = admit ()
let bpf_skb_pull_data #_ #_ _ _ = admit ()
let bpf_skb_adjust_room #_ #_ _ _ _ _ = admit ()
let bpf_l3_csum_replace #_ #_ _ _ _ _ _ = admit ()
let bpf_l4_csum_replace #_ #_ _ _ _ _ _ = admit ()

(* XDP + TC *)
let bpf_redirect #_ #_ _ _ = admit ()
let bpf_fib_lookup #_ #_ #_ _ _ _ _ = admit ()
let bpf_csum_diff #_ #_ _ _ _ _ _ = admit ()

(* TC + socket_filter *)
let bpf_skb_load_bytes #_ #_ _ _ _ _ = admit ()
