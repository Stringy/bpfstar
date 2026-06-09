#!/bin/bash
# Post-process KaRaMeL-generated C for BPF compatibility.
#
# Usage: postprocess.sh input.c output.bpf.c
#
# This script:
# 1. Removes the KaRaMeL header comment block
# 2. Removes extern declarations for BPF helpers (provided by preamble)
# 3. Rewrites map lookup to pass key by pointer (BPF convention)
# 4. Rewrites ringbuf reserve to include sizeof (BPF convention)
# 5. Cleans up resulting blank lines

set -euo pipefail

input="${1:?Usage: postprocess.sh input.c output.bpf.c}"
output="${2:?Usage: postprocess.sh input.c output.bpf.c}"

sed \
  -e '1,/^ \*\//d' \
  -e '/^extern /d' \
  -e 's/bpf_map_lookup_elem(/bpf_map_lookup_elem_val(/g' \
  -e 's/\([a-zA-Z_]*\) \*\([a-zA-Z_]*\) = bpf_ringbuf_reserve(\([^,]*\), \([^)]*\))/\1 *\2 = bpf_ringbuf_reserve_typed(\1, \3, \4)/g' \
  "$input" | sed '/^$/N;/^\n$/d' > "$output"
