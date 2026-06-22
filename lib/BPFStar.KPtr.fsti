(* BPFStar.KPtr -- Phantom-tagged kernel pointer types.

   Kernel pointers are opaque to BPF programmes -- you cannot
   dereference them directly, only pass them to helpers or use
   CO-RE reads. The phantom tag prevents mixing up pointers to
   different kernel struct types.

   Extracts to void* or the appropriate kernel struct pointer
   in C, depending on the extraction plugin. *)
module BPFStar.KPtr

(* Kernel struct tags. Add new constructors as needed. *)
type kernel_struct =
  | KTask         (* struct task_struct *)
  | KFile         (* struct file *)
  | KInode        (* struct inode *)
  | KCgroup       (* struct cgroup *)
  | KPath         (* struct path *)
  | KSocket       (* struct socket *)
  | KSkBuff       (* struct __sk_buff *)
  | KXdpMd        (* struct xdp_md *)
  | KPtRegs       (* struct pt_regs *)
  | KLinuxBinprm  (* struct linux_binprm *)

(* Opaque kernel pointer, tagged by the struct it points to.
   Cannot be dereferenced in Pulse -- only passed to helpers
   or used with CO-RE reads. *)
val kptr (s: kernel_struct) : Type0
