/* BPF programme: wrapper + extracted verified code.
   Includes the extracted C directly so everything compiles
   into a single BPF ELF object. */

#include "FileMonitor.c"
#include <bpf/bpf_tracing.h>

SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file *file)
{
    return __bpfstar_trace_file_open(file);
}
