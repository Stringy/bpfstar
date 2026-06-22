(* BPFStar.ProgType -- capability instances.

   Registers which programme types support which capabilities.
   Based on Linux kernel bpf_func_proto dispatch chains. *)
module BPFStar.ProgType

(* --- can_trace: tracing family ---
   kprobe, tracepoint, raw_tracepoint, fentry, fexit, LSM *)
instance can_trace_kprobe        : can_trace Kprobe        = { _ct = () }
instance can_trace_tracepoint    : can_trace Tracepoint    = { _ct = () }
instance can_trace_raw_tracepoint: can_trace RawTracepoint = { _ct = () }
instance can_trace_fentry        : can_trace Fentry        = { _ct = () }
instance can_trace_fexit         : can_trace Fexit         = { _ct = () }
instance can_trace_lsm           : can_trace LSM           = { _ct = () }

(* --- can_adv_trace: fentry, fexit, LSM ---
   tracing_prog_func_proto path *)
instance can_adv_trace_fentry : can_adv_trace Fentry = { _cat = () }
instance can_adv_trace_fexit  : can_adv_trace Fexit  = { _cat = () }
instance can_adv_trace_lsm    : can_adv_trace LSM    = { _cat = () }

(* --- can_func_ip: kprobe, fentry, fexit --- *)
instance can_func_ip_kprobe : can_func_ip Kprobe = { _cf = () }
instance can_func_ip_fentry : can_func_ip Fentry = { _cf = () }
instance can_func_ip_fexit  : can_func_ip Fexit  = { _cf = () }

(* --- can_lsm: LSM only --- *)
instance can_lsm_lsm : can_lsm LSM = { _cl = () }

(* --- can_kprobe: kprobe only --- *)
instance can_kprobe_kprobe : can_kprobe Kprobe = { _ck = () }

(* --- can_sk_storage: TC, cgroup, sock_ops, sk_msg, LSM,
   fentry, fexit --- *)
instance can_sk_storage_tc      : can_sk_storage TC         = { _cs = () }
instance can_sk_storage_cgroup  : can_sk_storage CgroupSock = { _cs = () }
instance can_sk_storage_sockops : can_sk_storage SockOps    = { _cs = () }
instance can_sk_storage_skmsg   : can_sk_storage SkMsg      = { _cs = () }
instance can_sk_storage_lsm     : can_sk_storage LSM        = { _cs = () }
instance can_sk_storage_fentry  : can_sk_storage Fentry     = { _cs = () }
instance can_sk_storage_fexit   : can_sk_storage Fexit      = { _cs = () }

(* --- can_xdp: XDP only --- *)
instance can_xdp_xdp : can_xdp XDP = { _cx = () }

(* --- can_tc: TC only --- *)
instance can_tc_tc : can_tc TC = { _ctc = () }

(* --- can_net_fwd: XDP + TC --- *)
instance can_net_fwd_xdp : can_net_fwd XDP = { _cn = () }
instance can_net_fwd_tc  : can_net_fwd TC  = { _cn = () }

(* --- can_skb_read: TC + socket_filter --- *)
instance can_skb_read_tc     : can_skb_read TC           = { _csr = () }
instance can_skb_read_filter : can_skb_read SocketFilter = { _csr = () }
