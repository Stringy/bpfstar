# BPFStar: Verified BPF programmes via Pulse
#
# Usage:
#   make fstar     # Build F* and Pulse from submodule (first time only)
#   make verify    # Verify the BPFStar library and examples
#   make extract   # Extract examples to C
#   make bpf       # Compile extracted C to BPF ELF objects
#   make all       # Everything: fstar + verify + extract + bpf
#   make clean     # Clean BPFStar build artefacts
#
# Prerequisites:
#   - OCaml 4.14+ and opam (for building F*)
#   - z3-4.8.5 and z3-4.13.3 on PATH
#   - clang with BPF target support (for make bpf)
#   - git submodule update --init --recursive
#
# The first `make fstar` takes ~15-20 minutes (3-stage bootstrap
# + ulib + Pulse library verification). Subsequent builds are
# incremental and only rebuild what changed.
#
# If you already have a system fstar.exe installed, set
# FSTAR_SYSTEM_EXE to skip the stage0 bootstrap and save ~5 min:
#   make fstar FSTAR_SYSTEM_EXE=$(which fstar.exe)

FSTAR_ROOT := $(CURDIR)/fstar
PULSE_ROOT := $(FSTAR_ROOT)/pulse

# Use the submodule's fstar.exe once built
export PATH := $(FSTAR_ROOT)/out/bin:$(PATH)

include $(PULSE_ROOT)/mk/common.mk

.DEFAULT_GOAL := verify

.PHONY: all
all: fstar verify extract bpf

# Build F* and Pulse from the submodule.
# Only needed once, or after updating the fstar submodule.
.PHONY: fstar
fstar:
ifdef FSTAR_SYSTEM_EXE
	$(MAKE) -C $(FSTAR_ROOT) -j$$(nproc) FSTAR_EXTERNAL_STAGE0=$(FSTAR_SYSTEM_EXE)
else
	$(MAKE) -C $(FSTAR_ROOT) -j$$(nproc)
endif

# Verify the BPFStar library
.PHONY: verify
verify:
	$(MAKE) -C lib PULSE_ROOT=$(PULSE_ROOT)
	$(MAKE) -C examples/minimal PULSE_ROOT=$(PULSE_ROOT) verify
	$(MAKE) -C examples/file_monitor PULSE_ROOT=$(PULSE_ROOT) verify

# Extract examples to C via Karamel
.PHONY: extract
extract:
	$(MAKE) -C examples/minimal PULSE_ROOT=$(PULSE_ROOT) extract
	$(MAKE) -C examples/file_monitor PULSE_ROOT=$(PULSE_ROOT) extract

# Compile extracted C to BPF ELF objects
.PHONY: bpf
bpf:
	$(MAKE) -C examples/minimal PULSE_ROOT=$(PULSE_ROOT) bpf
	$(MAKE) -C examples/file_monitor PULSE_ROOT=$(PULSE_ROOT) bpf

# Clean BPFStar build artefacts (does not clean fstar/)
.PHONY: clean
clean:
	$(MAKE) -C lib clean
	$(MAKE) -C examples/minimal clean
	$(MAKE) -C examples/file_monitor clean

# Deep clean: also clean F* and Pulse
.PHONY: distclean
distclean: clean
	$(MAKE) -C $(FSTAR_ROOT) clean
