PULSE_ROOT ?= ../../fstar/pulse
BPFSTAR_ROOT ?= ../..
OUTPUT_DIR ?= _output
OTHERFLAGS += --include $(BPFSTAR_ROOT)/lib
OTHERFLAGS += --warn_error -353

# Trigger C extraction for FileMonitor.fst
EXTRACT_C = FileMonitor.fst

# BPF-specific krml flags
KRML_FLAGS = \
  -minimal \
  -skip-compilation \
  -library 'BPFStar.*' \
  -no-prefix FileMonitor \
  -flinux-ints \
  -warn-error -2-4-15 \
  -add-early-include '"bpfstar_preamble.h"'

# Extra krml dependencies
$(OUTPUT_DIR)/FileMonitor.c: $(addprefix $(OUTPUT_DIR)/,\
	BPFStar_Helpers.krml \
	BPFStar_Map.krml \
	BPFStar_RingBuf.krml \
	BPFStar_Types.krml \
	FStar_Pervasives.krml \
	FStar_Pervasives_Native.krml \
	FStar_Int_Cast.krml)

# BPF compilation
CLANG ?= clang
BPF_CFLAGS = -target bpf -O2 -g \
  -I $(BPFSTAR_ROOT)/bpf \
  -I $(BPFSTAR_ROOT)/libbpf/src \
  -I $(BPFSTAR_ROOT)/libbpf/include/uapi \
  -I $(OUTPUT_DIR)

$(OUTPUT_DIR)/%.bpf.o: $(OUTPUT_DIR)/%.c
	$(call msg, "BPF", $(notdir $@))
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Compile wrapper (which #includes the extracted .c) into one BPF object.
$(OUTPUT_DIR)/file_monitor.bpf.o: wrapper.bpf.c $(OUTPUT_DIR)/FileMonitor.c
	$(call msg, "BPF", $(notdir $@))
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

.PHONY: bpf
bpf: $(OUTPUT_DIR)/file_monitor.bpf.o

include $(PULSE_ROOT)/mk/test.mk
