/* BPFStar preamble -- included before all generated BPF C code.

   Bridges between Karamel's C output conventions and the BPF C
   environment provided by libbpf. The extraction plugin
   (ExtractPulseBPF) generates correct BPF helper calls directly,
   so this preamble only needs type aliases. */

#ifndef BPFSTAR_PREAMBLE_H
#define BPFSTAR_PREAMBLE_H

#include <linux/types.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>

/* Type aliases for Karamel's -flinux-ints output. */
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* Licence -- required by the BPF loader. */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#endif /* BPFSTAR_PREAMBLE_H */
