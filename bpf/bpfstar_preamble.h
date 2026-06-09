/* BPFStar preamble -- included before all generated BPF C code.

   This header bridges between Karamel's C output conventions and
   the BPF C environment provided by libbpf. */

#ifndef BPFSTAR_PREAMBLE_H
#define BPFSTAR_PREAMBLE_H

#include <linux/types.h>
#include <stddef.h>
#include <bpf/bpf_helpers.h>

/* Type aliases for Karamel's -flinux-ints output.
   Karamel emits u8, u16, u32, u64 etc. which are the Linux kernel
   short type names. These are not always defined in userspace
   headers, so we alias them from the __u* types. */
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* BPFStar runtime support. */

/* release_map_value is a no-op -- the BPF verifier tracks map
   value pointer lifetime, not the programme. In Pulse it exists
   to consume the map_value separation logic permission. */
static inline __attribute__((always_inline))
void release_map_value(void *map, void *value)
{
  (void)map;
  (void)value;
}

/* map_lookup: convenience wrapper that takes key by value,
   puts it on the stack, and calls bpf_map_lookup_elem with
   a pointer. This matches what the Pulse fn map_lookup does. */
#define map_lookup(map, key) \
  ({ __typeof__(key) __bpfstar_key = (key); \
     bpf_map_lookup_elem((map), &__bpfstar_key); })

/* Licence -- required by the BPF loader. */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

#endif /* BPFSTAR_PREAMBLE_H */
