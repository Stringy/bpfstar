/* BPFStar preamble -- included before all generated BPF C code.
   Provides type definitions and BPF helper declarations. */

#ifndef BPFSTAR_PREAMBLE_H
#define BPFSTAR_PREAMBLE_H

#include <linux/types.h>
#include <stddef.h>

/* Type aliases for Linux kernel integer types used by KaRaMeL
   with -flinux-ints */
typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

/* BPF helper function declarations.
   These are provided by the BPF runtime. The function pointer
   pattern is the standard way to declare BPF helpers. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *) 125;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;

/* BPFStar library wrappers.
   These adapt between the Pulse calling convention and the BPF
   calling convention. */

/* Map lookup: Pulse passes the key by value, BPF needs a pointer.
   We use a GCC statement expression to take the address. */
#define bpf_map_lookup_elem_val(map, key) \
  ({ __typeof__(key) __bpfstar_k = (key); \
     bpf_map_lookup_elem((map), &__bpfstar_k); })

/* Ring buffer reserve: Pulse omits the size parameter since it's
   determined by the type. We compute it with sizeof. */
#define bpf_ringbuf_reserve_typed(type, rb, flags) \
  (type *)bpf_ringbuf_reserve((rb), sizeof(type), (flags))

/* Release map value is a no-op at runtime -- the BPF verifier
   tracks map value lifetime, not the programme. */
static inline __attribute__((always_inline))
void release_map_value(void *map, void *value) { (void)map; (void)value; }

/* Licence */
char LICENSE[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

/* SEC macro for programme entry points */
#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#endif /* BPFSTAR_PREAMBLE_H */
