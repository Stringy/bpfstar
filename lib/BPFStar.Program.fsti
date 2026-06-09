(* BPFStar.Program -- BPF programme entry point annotations.

   Use [@@ CSection "section_name"] from FStar.Attributes to
   mark functions as BPF programme entry points. The section
   name determines the programme type and attachment point.

   Common section names:
   - "kprobe/<func>"          -- kernel probe
   - "tp/<cat>/<name>"        -- tracepoint
   - "tp_btf/<name>"          -- BTF-enabled tracepoint
   - "lsm/<hook>"             -- LSM security hook
   - "xdp"                    -- express data path

   Example:
     [@@ CSection "lsm/file_open"]
     fn trace_file_open (...) { ... }

   This is extracted to:
     __attribute__((section("lsm/file_open")))
     void trace_file_open(...) { ... }
*)
module BPFStar.Program
