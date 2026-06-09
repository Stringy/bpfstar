(* BPFStar.Program -- BPF programme entry point annotations.

   Provides the bpf_section attribute for marking functions as
   BPF programme entry points. During extraction, this attribute
   is emitted as SEC("...") in the generated C code.

   Example usage:
     [@@ bpf_section "lsm/file_open"]
     fn trace_file_open (...)
       requires ...
       ensures  ...
     { ... }
*)
module BPFStar.Program

(* Attribute to mark a function as a BPF programme entry point.
   The string argument specifies the ELF section name, which
   determines the programme type and attachment point.

   Common section names:
   - "kprobe/<func>"          -- kernel probe
   - "kretprobe/<func>"       -- kernel return probe
   - "tp/<cat>/<name>"        -- tracepoint
   - "tp_btf/<name>"          -- BTF-enabled tracepoint
   - "fentry/<func>"          -- function entry tracing
   - "fexit/<func>"           -- function exit tracing
   - "lsm/<hook>"             -- LSM security hook
   - "xdp"                    -- express data path
   - "tc"                     -- traffic control
   - "raw_tp/<name>"          -- raw tracepoint *)
val bpf_section : string -> unit

(* BPF licence declaration. Must be GPL-compatible to access
   all BPF helpers. Extracted as:
     char LICENSE[] SEC("license") = "..."; *)
val bpf_license : string -> unit
