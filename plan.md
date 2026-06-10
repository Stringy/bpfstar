# BPFStar: Verified BPF Programmes via Pulse

## Overview

BPFStar is a Pulse library for writing formally verified BPF programmes.
Programmes are written in Pulse's separation logic DSL, verified by F*, and
extracted to BPF-compatible C that compiles with `clang -target bpf`.

## Current Status

**Phases 1 and 2 are complete.** The full pipeline works end-to-end:

```
Minimal.fst  ->  F* verify  ->  .krml  ->  krml  ->  .c  ->  clang -target bpf  ->  .bpf.o
```

The generated `.bpf.o` has correct ELF sections (`.maps` for map definitions,
named sections like `tp/raw_syscalls/sys_enter` for programmes) and is loadable
by libbpf/aya.

## Repository Structure

```
bpfstar/
  fstar/                              # git submodule (F* fork, branch: bpfstar-extraction)
    pulse/src/extraction/
      ExtractPulseBPF.fst[i]          # BPF extraction plugin (~250 lines)
    ulib/FStar.Attributes.fsti        # +CSection, +CVerbatim attributes
    karamel/lib/
      Common.ml                       # +Section, +Verbatim flags
      CStarToC11.ml                   # section attribute emission
      PrintC.ml                       # __attribute__((section(...))) output
  libbpf/                             # git submodule (BPF helper headers)
  lib/
    BPFStar.fst                       # top-level re-export
    BPFStar.Map.fsti/fst              # map operations + definitions
    BPFStar.RingBuf.fsti/fst          # ring buffer with linear ownership
    BPFStar.Helpers.fsti/fst          # BPF helper function specs
    BPFStar.Types.fsti/fst            # scalar types, flags, return codes
    BPFStar.Program.fsti/fst          # documentation (CSection replaces bpf_section)
  bpf/
    bpfstar_preamble.h                # type aliases + licence
  examples/
    minimal/                          # tracepoint PID filter
    file_monitor/                     # (next: FACT trace_file_open port)
  Makefile
  plan.md
```

## Architecture

### The Extraction Plugin (ExtractPulseBPF.fst)

The core of BPFStar's extraction lives in a single F* file that registers
as a pre-translation hook alongside ExtractPulse and ExtractPulseC. It
handles three categories of translation:

**Expression hooks** (`register_pre_translate_expr`):

| Pulse call | Generated Krml AST | C output |
|---|---|---|
| `bpf_get_current_pid_tgid ()` | `EApp("bpf_get_current_pid_tgid", [EUnit])` | `bpf_get_current_pid_tgid()` |
| `map_lookup m k` | `ELet(__key = k, EApp("bpf_map_lookup_elem", [EAddrOf m, EAddrOf __key]))` | `u32 __key = k; bpf_map_lookup_elem(&m, &__key)` |
| `release_map_value m p` | `EUnit` | *(erased)* |
| `bpf_ringbuf_reserve rb sz fl` | `EApp("bpf_ringbuf_reserve", [EAddrOf rb, sz, fl])` | `bpf_ringbuf_reserve(&rb, sz, fl)` |
| `bpf_ringbuf_submit p fl` | `EApp("bpf_ringbuf_submit", [p, fl])` | `bpf_ringbuf_submit(p, fl)` |

**Type hooks** (`register_pre_translate_type_without_decay`):

| Pulse type | Krml type | C type |
|---|---|---|
| `bpf_map kt vt` | `TAny` | `void *` (opaque) |
| `bpf_ringbuf` | `TAny` | `void *` (opaque) |

**Let-binding hooks** (`register_pre_translate_let`):

Map and ring buffer definitions are intercepted and emitted as `DGlobal`
declarations with `Verbatim` + `Prologue` flags. The Prologue contains the
BTF struct definition; Verbatim suppresses the normal `void *` declaration.

| Pulse definition | C output |
|---|---|
| `let m = define_hash_map 8192ul` | `struct { __uint(type, BPF_MAP_TYPE_HASH); ... } m SEC(".maps");` |
| `let rb = define_ringbuf 262144ul` | `struct { __uint(type, BPF_MAP_TYPE_RINGBUF); ... } rb SEC(".maps");` |

### F*/Karamel Extensions

Two new attributes added to the F*/Karamel pipeline:

**CSection** -- places a declaration in a named ELF section:
```fstar
[@@ CSection "tp/raw_syscalls/sys_enter"]
fn trace_sys_enter () ...
```
Flows through: `FStar.Attributes.CSection` -> ML `CSection` meta ->
Krml `Section` flag -> Karamel `Section` flag -> `C11.extra.section` ->
`__attribute__((section(...)))` in C output.

**CVerbatim** -- suppresses the declaration, keeps only Prologue/Epilogue:
```fstar
[@@ CVerbatim; CPrologue "struct { ... } my_map SEC(\".maps\");"]
let my_map = ...
```
Used internally by the extraction plugin for map definitions.

### The Preamble

`bpf/bpfstar_preamble.h` is minimal -- just type aliases (`u32`/`u64` etc.
for Karamel's `-flinux-ints` output) and a licence declaration. All BPF
helper translations are in the extraction plugin, not in C macros.

### Karamel Flags

The extraction uses these krml flags:
- `-minimal` -- no krmllib dependency
- `-skip-compilation` -- we compile with clang, not gcc
- `-library 'BPFStar.*'` -- treat library as abstract
- `-no-prefix Minimal` -- no module prefix on user code
- `-flinux-ints` -- emit `u32`/`u64` instead of `uint32_t`/`uint64_t`
- `-add-early-include '"bpfstar_preamble.h"'` -- inject preamble

## The BPFStar Library

### Map Operations

Map lookup takes the key by value. The extraction plugin handles
stack-allocating the key and passing its address:

```fstar
val map_lookup (#kt #vt: Type0) (m: bpf_map kt vt) (k: kt)
  : stt (ref vt)
    (requires map_perm m)
    (ensures fun r ->
      map_perm m **
      (if is_null r then emp
       else exists* v. map_value m r v))
```

The caller must check `is_null` before use. Non-null means you hold a
`map_value` permission (a borrow from the map) that must be released.

### Map Definitions

```fstar
let pid_filter : bpf_map UInt32.t UInt32.t = define_hash_map 8192ul
let events : bpf_ringbuf = define_ringbuf 262144ul
```

Available map types: `define_hash_map`, `define_array_map`,
`define_lru_hash_map`, `define_percpu_array_map`, `define_ringbuf`.

### Ring Buffer

Ring buffer reservation returns a nullable pointer. The non-null case gives
a linear `ringbuf_reservation` permission that must be consumed by `submit`
or `discard` on every code path.

### Helper Functions

10 BPF helper functions are specified. All are axiomatised (`admit()`) since
they are opaque BPF VM operations. The extraction plugin emits direct calls
to the real BPF helper functions.

### Separation Logic Guarantees

The library enforces at verification time:
- **Null safety**: map lookup and ringbuf reserve return nullable refs;
  you cannot dereference without checking `is_null`
- **Resource linearity**: ringbuf reservations must be submitted or
  discarded on every code path
- **Borrow discipline**: map value pointers must be released before the
  programme returns

## Build System

```
make fstar      # build F*/Pulse from submodule (~20 min first time, ~7s incremental)
make verify     # verify library and examples
make extract    # extract to C via Karamel
make bpf        # compile to BPF ELF objects
make all        # everything
make clean      # clean BPFStar artefacts
make distclean  # also clean F*/Pulse
```

## Completed Work

### Phase 1: Foundation (DONE)

- BPFStar library with separation logic specs
- Minimal tracepoint example verified in Pulse
- F* submodule with Karamel build

### Phase 2: Extraction (DONE)

- ExtractPulseBPF extraction plugin
- CSection attribute for ELF sections
- CVerbatim flag for map definitions
- End-to-end pipeline: `.fst` -> `.bpf.o`
- No post-processing, no macros
- libbpf submodule for BPF headers
- Make targets for full pipeline

### Phase 3: Real-World Programme (DONE - simplified)

- Ported FACT's `trace_file_open` control flow to Pulse
- Overlayfs deduplication pattern (LRU hash: lookup + update + delete)
- Inode tracking (hash map: lookup + update)
- Ring buffer event submission (reserve + write + submit)
- Multiple map definitions in `.maps` section
- `map_update` and `map_delete` convenience wrappers
- Programme entry points with correct return type (`Int32.t` / `s32`)
  and single context parameter (`UInt64.t` / `u64`)

**What was simplified:** CO-RE reads (`BPF_CORE_READ`) for kernel struct
field access are not yet supported. The file monitor uses placeholder
values for inode number and device instead of reading from the kernel
`struct file`. Process info filling, path resolution, and metrics
tracking were also omitted. These need additional library support.

## Next Steps

### Phase 3.5: BPF_PROG and CO-RE (in progress)

**Goal:** Support typed context access for programme entry points.

1. **BPF_PROG macro** -- generate `SEC("...") int BPF_PROG(name, args)`
   instead of raw `int name(u64 ctx)`. This gives typed access to hook
   arguments without manual casting. Requires extraction plugin changes
   to emit the macro invocation.

2. **CO-RE field access** -- `BPF_CORE_READ(ptr, field1, field2)` for
   reading kernel struct fields with BTF relocation. Needs:
   - A `kptr` type for kernel pointers
   - `core_read` helper that extracts to `BPF_CORE_READ()`
   - Field accessor definitions for kernel structs (at least `struct file`)

### Phase 4: Advanced Features

1. **CO-RE existence checks** -- `bpf_core_type_exists`,
   `bpf_core_field_exists` for kernel version portability
2. **Bounded loop support** -- verify Pulse `while` loops extract
   to BPF-verifier-friendly bounded `for` loops
3. **LPM trie maps** -- `define_lpm_trie_map` for path prefix matching
4. **Per-CPU map semantics** -- model the no-contention guarantee
5. **Tail calls** -- programme arrays, cross-programme state via maps
6. **`bpf_loop` callback support** -- model the callback pattern
7. **Additional programme types** -- XDP, TC, fentry/fexit
8. **Real separation logic proofs** -- move beyond `admit()` for
   library operations; prove resource linearity formally
9. **Process info helpers** -- `bpf_get_current_task_btf`,
   `bpf_get_current_comm`, lineage traversal

## Key Risks (Updated)

1. ~~**Karamel extraction for BPF C**~~ -- RESOLVED. The ExtractPulseBPF
   plugin handles all BPF-specific translation. No post-processing needed.

2. ~~**BPF map definitions**~~ -- RESOLVED. The Verbatim flag + Prologue
   mechanism emits correct BTF struct definitions in `.maps` sections.

3. **CO-RE / BPF_PROG support** -- the main remaining gap for real-world
   programmes. `BPF_CORE_READ` chains and `BPF_PROG` macro invocations
   have no direct Krml AST representation. Will need extraction plugin
   hooks to emit these as formatted C text.

4. **Pulse prover limitations** -- nested `if/else` branches after
   `map_lookup` (which returns conditional `slprop`) can confuse the
   prover. Workaround: extract null-check logic into separate helper
   functions to isolate the proof context.

5. **OCaml Marshal constructor alignment** -- the Krml flag type in F*
   must have constructor indices matching Karamel's `Common.flag` type.
   Padding constructors are used to maintain alignment. This is fragile
   and should be documented as a maintenance constraint.

6. **Verification performance** -- the file monitor example verifies
   in seconds, but larger programmes with many map operations may
   stress F*'s normaliser.

## Lessons Learned

1. **The extraction plugin approach works well.** Rather than modifying
   Karamel's core, registering pre-translation hooks lets us intercept
   BPF-specific patterns and emit the correct Krml AST. This keeps
   changes contained and avoids breaking non-BPF extraction.

2. **API design must match the C calling convention.** Early attempts
   used Pulse's `option` type for nullable returns and pass-by-value
   for map keys. These produced valid F* but un-extractable C. Switching
   to nullable `ref` returns and pointer-based keys (with the plugin
   handling `&`) produced clean extraction.

3. **Karamel's flag system is powerful but fragile.** Adding new flags
   requires careful constructor alignment between F* and Karamel's
   OCaml types (they're marshalled as binary values, not JSON). New
   attributes (CSection, CVerbatim) work well but need padding
   constructors to maintain index alignment.

4. **libbpf headers are the right dependency.** Hand-declaring BPF
   helpers in a preamble was brittle. Using libbpf's `bpf_helpers.h`
   and `bpf_helper_defs.h` gives us all helper declarations, the SEC
   macro, and BTF macros (`__uint`, `__type`) for free.

5. **Verbatim declarations solve the BTF struct problem.** BPF map
   definitions can't be expressed through Karamel's normal `DGlobal`
   AST node. Emitting the full definition as Prologue text and
   suppressing the generated declaration (via the new Verbatim flag)
   is clean and works with the existing pipeline.
