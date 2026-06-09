# BPFStar: Verified BPF Programmes via Pulse

## Overview

BPFStar is a Pulse library for writing formally verified BPF programmes.
Programmes are written in Pulse's separation logic DSL, verified by F*, and
extracted to BPF-compatible C that compiles with `clang -target bpf`.

The library provides:

- Separation logic specifications for BPF maps, ring buffers, and helper
  functions
- C struct type definitions for BPF contexts and events (built on
  `Pulse.C.Types`)
- An extraction path to BPF-loadable ELF objects

## Repository Structure

```
bpfstar/
  fstar/                          # git submodule -> F* fork
  lib/
    BPFStar.fst                   # Top-level module (re-exports)
    BPFStar.Map.fsti              # BPF map types and operations
    BPFStar.Map.fst
    BPFStar.RingBuf.fsti          # Ring buffer with linear ownership
    BPFStar.RingBuf.fst
    BPFStar.Helpers.fsti          # BPF helper function specs
    BPFStar.Helpers.fst
    BPFStar.Types.fsti            # Common BPF types (context structs, scalars)
    BPFStar.Types.fst
    BPFStar.Program.fsti          # Programme entry point annotation
    BPFStar.Program.fst
    fstar.include                 # F* include path configuration
  examples/
    minimal/                      # Minimal tracepoint programme
    file_monitor/                 # File activity monitor (FACT-inspired)
  Makefile
  plan.md
```

## Background

### What We Learned from bpf-verifier

The [bpf-verifier](https://github.com/stringy/bpf-verifier) project proved
that BPF programmes can be formally verified against specifications using F*.
Key lessons:

1. **"Rust computes, F* checks"** -- pushing analysis to Rust and having F*
   validate witnesses avoided exponential blowup in the normaliser.
2. **Layered safety** (stack bounds, type safety, null safety as independent
   boolean checkers) worked well for separating concerns.
3. **Path-based execution** for non-deterministic helpers (map lookups returning
   NULL or a value) was essential for scalability.
4. **The gap**: bpf-verifier verifies *compiled* BPF bytecode. It cannot help
   you *write* correct BPF. Pulse can.

The bpf-verifier already had an experimental Pulse helpers module
(`BPF.Pulse.Helpers.fsti/fst`) modelling `bpf_ringbuf_reserve/submit` with
separation logic predicates. BPFStar builds on this direction with a complete
library design informed by real-world BPF programme analysis.

### What Real-World BPF Programmes Need

Analysis of [stackrox/fact](https://github.com/stackrox/fact) (9 LSM
programmes, file activity monitoring) and
[falcosecurity/libs](https://github.com/falcosecurity/libs) (345 programmes,
system call monitoring):

| Feature | FACT | Falco | Pulse Support Today |
|---------|------|-------|---------------------|
| Map operations (lookup/update/delete) | Yes | Yes | No -- needs library |
| Ring buffer (reserve/submit/discard) | Yes | Yes | No -- needs library |
| BPF helpers (probe_read, pid, comm) | 17 helpers | 20+ helpers | No -- needs library |
| C structs with field access | Yes | Yes | **Yes** -- `Pulse.C.Types.Struct` |
| Bounded loops | bpf_loop | Static bounds | **Yes** -- `Pulse.Lib.Loops` |
| Per-CPU scratch buffers (map-as-heap) | Yes | Yes (128KB) | No -- needs library |
| NULL checks after map lookup | Yes | Yes | **Yes** -- `option` type |
| Pointer arithmetic with bounds | Limited | Extensive | **Partial** -- `Pulse.Lib.ArrayPtr` |
| Tail calls | No | 23 sites | No -- needs library |
| CO-RE / BTF field access | Extensive | Extensive | No -- deferred |
| Global variables (const volatile) | Yes | Yes | No -- needs extraction |

### Pulse Capabilities We Build On

Pulse already provides everything needed for the core library:

- **`Pulse.C.Types.Struct`** -- C struct definitions with field access
- **`Pulse.C.Types.Scalar`** -- Fixed-width integer types (U8, U16, U32, U64)
- **`Pulse.C.Types.Array`** -- Fixed-size C arrays
- **`Pulse.Lib.ArrayPtr`** -- Pointer arithmetic with bounds tracking
- **`Pulse.Lib.Reference`** -- Mutable references with fractional permissions
- **Separation logic** -- `slprop`, `**`, `exists*`, `emp`, `pure`
- **`option` type** -- Natural model for nullable BPF returns
- **Bounded loops** -- While loops with invariants and decreasing measures
- **`stt_atomic`** -- Atomic actions (for helpers that don't modify programme state)
- **C extraction via Karamel** -- Existing `.fst -> .krml -> .c` pipeline

## Design Decisions

### Map Operations

Map lookup returns `option (ref vt)`, forcing NULL checks via pattern matching:

```fstar
fn bpf_map_lookup_elem (#kt #vt: Type) (m: bpf_map kt vt) (k: ref kt)
  requires map_perm m ** pts_to k kv
  returns  r: option (ref vt)
  ensures  map_perm m ** pts_to k kv **
           (match r with
            | Some p -> map_value_perm m p
            | None -> emp)
```

After lookup, the caller holds a `map_value_perm` -- a borrow from the map.
This must be consumed before the map can be used for another operation. This
models the BPF verifier's rule that map value pointers are only valid until the
programme returns or the entry is deleted.

Map update and delete:

```fstar
fn bpf_map_update_elem (#kt #vt: Type) (m: bpf_map kt vt)
    (k: ref kt) (v: ref vt) (flags: U64.t)
  requires map_perm m ** pts_to k _ ** pts_to v _
  returns  r: I32.t
  ensures  map_perm m ** pts_to k _ ** pts_to v _

fn bpf_map_delete_elem (#kt #vt: Type) (m: bpf_map kt vt) (k: ref kt)
  requires map_perm m ** pts_to k _
  returns  r: I32.t
  ensures  map_perm m ** pts_to k _
```

### Ring Buffer

Ring buffer reservation produces a linear resource that must be submitted or
discarded:

```fstar
fn bpf_ringbuf_reserve (#t: Type) (rb: bpf_ringbuf) (size: U32.t)
  requires ringbuf_perm rb
  returns  r: option (ref t)
  ensures  ringbuf_perm rb **
           (match r with
            | Some p -> ringbuf_reservation p
            | None -> emp)

fn bpf_ringbuf_submit (#t: Type) (p: ref t)
  requires ringbuf_reservation p ** pts_to p _
  ensures  emp    // ownership consumed

fn bpf_ringbuf_discard (#t: Type) (p: ref t)
  requires ringbuf_reservation p
  ensures  emp    // ownership consumed
```

The key insight: `ringbuf_reservation` is a linear slprop. Pulse's type system
prevents forgetting to submit or discard -- the programme will not typecheck if
the reservation is not consumed on every path.

### Helper Functions

Helpers are axiomatised (implemented via `admit()`) since they are opaque BPF VM
operations. Extraction emits calls to the real BPF helpers.

Three categories:

**Pure queries** (no pre/postcondition beyond emp):

- `bpf_get_current_pid_tgid`
- `bpf_get_current_uid_gid`
- `bpf_ktime_get_boot_ns`
- `bpf_get_smp_processor_id`
- `bpf_get_prandom_u32`

**Memory readers** (require destination buffer ownership):

- `bpf_probe_read_kernel`
- `bpf_probe_read_user`
- `bpf_probe_read_kernel_str`
- `bpf_get_current_comm`

**Map/ringbuf operations** (covered above):

- `bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`
- `bpf_ringbuf_reserve`, `bpf_ringbuf_submit`, `bpf_ringbuf_discard`

### Programme Entry Points

BPF programmes need ELF section annotations. We model this as an F* attribute:

```fstar
[@@ bpf_section "lsm/file_open"]
fn trace_file_open (file: lsm_file_open_ctx)
  requires ctx_perm file
  returns  r: I32.t
  ensures  emp
```

During extraction, the `bpf_section` attribute emits `SEC("lsm/file_open")` on
the C function. This requires a small patch to the F* fork's C extraction
backend -- the only Pulse-side change in Phase 1.

### Context Types

Each BPF programme type receives a different context. We define these as Pulse C
structs using the existing `Pulse.C.Types` framework:

```fstar
// LSM file_open context
define_struct "lsm_file_open_ctx" [
  ("file", scalar (ptr file_struct_t));
]

// Tracepoint context for sys_enter
define_struct "tp_sys_enter_ctx" [
  ("id",   scalar U64.t);
  ("args", array U64.t 6);
]
```

These are purely library-level -- no Pulse changes needed.

### What We Do NOT Model Initially

- **CO-RE**: Programmes target a specific kernel version. CO-RE relocations
  happen naturally when `clang -target bpf -g` compiles against a `vmlinux.h`
  with `preserve_access_index`.
- **Tail calls**: Deferred to Phase 4. Requires cross-programme reasoning.
- **Per-CPU map semantics**: Treated as regular maps initially. Per-CPU is a
  deployment optimisation, not a correctness concern for single-programme
  verification.
- **`bpf_loop` callbacks**: Deferred. Use Pulse's native bounded loops instead.
- **Architecture-conditional compilation**: Deferred. Target x86_64 initially.

## Extraction Pipeline

```
.fsti/.fst  ->  F* check  ->  Karamel (.krml)  ->  C (.c)  ->  clang -target bpf  ->  .bpf.o
```

The extracted C needs:

1. `#include "vmlinux.h"` and `#include <bpf/bpf_helpers.h>` preamble
2. `SEC("...")` annotations on entry points (from `bpf_section` attribute)
3. `char LICENSE[] SEC("license") = "Dual BSD/GPL";`
4. `__always_inline` on non-entry-point functions
5. BPF helper calls emitted as direct function calls (declared in
   `bpf_helpers.h`)

Items 1-4 require a small BPF-aware post-processing step or Karamel extension.
Item 5 should work naturally if the extraction maps `BPFStar.Helpers.*` to the
correct C function names.

## Phased Implementation

### Phase 1: Foundation

**Goal:** Write and verify a minimal BPF programme in Pulse.

1. Create repo, add F* submodule, set up Makefile
2. Implement `BPFStar.Map` -- map type, lookup/update/delete with sep logic
   specs
3. Implement `BPFStar.RingBuf` -- reserve/submit/discard with linear ownership
4. Implement `BPFStar.Helpers` -- 10 core helpers (pid, time, comm, probe_read,
   map ops, ringbuf ops)
5. Implement `BPFStar.Types` -- context types for tracepoint and LSM
6. Implement `BPFStar.Program` -- entry point annotation
7. Write `examples/minimal/` -- a tracepoint that reads pid, checks a map,
   writes to ringbuf
8. Verify it typechecks in F*/Pulse

**Milestone:** Pulse verifies a real BPF programme specification.

### Phase 2: Extraction

**Goal:** Extract the Phase 1 programme to compilable BPF C.

1. Add `bpf_section` attribute support to F* fork's extraction backend
2. Create BPF-specific Karamel post-processing (preamble, LICENSE, inline
   annotations)
3. Map `BPFStar.Helpers.*` to C helper function names in extraction
4. Build end-to-end pipeline: `.fst -> .c -> .bpf.o`
5. Test: load the compiled object with aya or libbpf

**Milestone:** End-to-end from Pulse source to loadable BPF object.

### Phase 3: Real-World Programme

**Goal:** Port a real FACT programme to Pulse.

1. Port `trace_file_open` from stackrox/fact
2. Model FACT's event struct, inode_key, process info
3. Handle overlayfs deduplication pattern (map lookup + conditional
   update/delete)
4. Handle path resolution with bounded loops
5. Verify functional properties (events contain correct data, maps maintained
   correctly)

**Milestone:** A production-grade BPF programme written and verified in Pulse.

### Phase 4: Advanced Features

1. Tail call support (programme arrays, cross-programme state via maps)
2. Per-CPU map semantics
3. CO-RE library (`bpf_core_read`, `bpf_core_field_exists`)
4. `bpf_loop` callback support
5. BPF-specific refinement types (stack size < 512, bounded loop counts)
6. Additional programme types (XDP, TC, fentry/fexit)

## Key Risks

1. **Karamel extraction for BPF C**: Karamel targets standard C. BPF C has
   restrictions (no recursion, no function pointers, 512-byte stack). If Karamel
   generates non-BPF-compatible C, we may need a post-processing pass or a
   dedicated BPF extraction backend (like pulse2rust but for BPF).

2. **Pulse C types vs BPF struct layout**: BPF structs must have exact memory
   layout matching kernel expectations. We need to verify that
   `Pulse.C.Types.Struct` extraction produces correctly-laid-out C structs.

3. **Map value lifetime**: BPF map value pointers are invalidated when the
   programme returns. Pulse's separation logic naturally models this (the
   `map_value_perm` is consumed), but we need to ensure the extraction does not
   introduce use-after-return patterns.

4. **Verification performance**: Large BPF programmes (like Falco's `execve`
   handler split across 3 tail-called programmes) may stress F*'s normaliser.
   The bpf-verifier project showed that path explosion is the main bottleneck --
   Pulse's approach should avoid this since we are verifying source-level code,
   not enumerating bytecode paths.
