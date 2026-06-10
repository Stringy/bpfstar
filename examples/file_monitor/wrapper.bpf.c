/* BPF_PROG entry point wrappers.
   These provide typed context access via the BPF_PROG macro and
   forward to the verified inner functions extracted from Pulse. */

#include "FileMonitor.h"
#include <bpf/bpf_tracing.h>

SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file *file)
{
    return __bpfstar_trace_file_open(file);
}
