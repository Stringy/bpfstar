PULSE_ROOT ?= ../../fstar/pulse
BPFSTAR_ROOT ?= ../..
OUTPUT_DIR ?= _output
OTHERFLAGS += --include $(BPFSTAR_ROOT)/lib
OTHERFLAGS += --include $(BPFSTAR_ROOT)/lib/_cache
OTHERFLAGS += --warn_error -353

# Trigger C extraction for Minimal.fst
EXTRACT_C = Minimal.fst

# BPF-specific krml flags.
# Note: test.mk adds -skip-makefiles, -bundle $*=*, and -skip-linking
KRML_FLAGS = \
  -minimal \
  -skip-compilation \
  -library 'BPFStar.*' \
  -no-prefix Minimal \
  -flinux-ints \
  -warn-error -2-4-15 \
  -add-early-include '"bpfstar_preamble.h"'

# Extra krml dependencies (BPFStar library + FStar pervasives)
$(OUTPUT_DIR)/Minimal.c: $(addprefix $(OUTPUT_DIR)/,\
	BPFStar_Helpers.krml \
	BPFStar_Map.krml \
	BPFStar_RingBuf.krml \
	BPFStar_Types.krml \
	FStar_Pervasives.krml \
	FStar_Pervasives_Native.krml \
	FStar_Int_Cast.krml)

# BPF compilation: .c -> .bpf.o
CLANG ?= clang
BPF_CFLAGS = -target bpf -O2 -g \
  -I $(BPFSTAR_ROOT)/bpf \
  -I $(BPFSTAR_ROOT)/libbpf/src \
  -I $(BPFSTAR_ROOT)/libbpf/include/uapi \
  -I $(OUTPUT_DIR)

$(OUTPUT_DIR)/%.bpf.o: $(OUTPUT_DIR)/%.c
	$(call msg, "BPF", $(notdir $@))
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# The bpf target builds the BPF ELF object
.PHONY: bpf
bpf: $(OUTPUT_DIR)/Minimal.bpf.o

include $(PULSE_ROOT)/mk/test.mk
