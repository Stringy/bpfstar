# BPFStar: Verified BPF programmes via Pulse
#
# Usage:
#   make fstar     # Build F* and Pulse from submodule (first time only)
#   make verify    # Verify the BPFStar library
#   make examples  # Verify the examples
#   make all       # Build everything (fstar + verify + examples)
#   make clean     # Clean BPFStar build artefacts
#
# Prerequisites:
#   - OCaml 4.14+ and opam (for building F*)
#   - z3-4.8.5 and z3-4.13.3 on PATH
#   - git submodule update --init --recursive

FSTAR_ROOT := $(CURDIR)/fstar
PULSE_ROOT := $(FSTAR_ROOT)/pulse

# Use the submodule's fstar.exe
export PATH := $(FSTAR_ROOT)/out/bin:$(PATH)

include $(PULSE_ROOT)/mk/common.mk

.DEFAULT_GOAL := verify

.PHONY: all
all: fstar verify examples

# Build F* and Pulse from the submodule.
# Only needed once, or after updating the fstar submodule.
.PHONY: fstar
fstar:
	$(MAKE) -C $(FSTAR_ROOT) -j$$(nproc)

# Verify the BPFStar library
.PHONY: verify
verify:
	$(MAKE) -C lib PULSE_ROOT=$(PULSE_ROOT)

# Verify the examples
.PHONY: examples
examples:
	$(MAKE) -C examples/minimal PULSE_ROOT=$(PULSE_ROOT)

# Clean BPFStar build artefacts (does not clean fstar/)
.PHONY: clean
clean:
	$(MAKE) -C lib clean
	$(MAKE) -C examples/minimal clean

# Deep clean: also clean F* and Pulse
.PHONY: distclean
distclean: clean
	$(MAKE) -C $(FSTAR_ROOT) clean
