# BPFStar: Verified BPF programmes via Pulse
#
# This Makefile follows the Pulse build conventions. It assumes that the
# F* submodule (fstar/) has been built and the Pulse library installed
# into fstar/pulse/out/.
#
# Usage:
#   make pulse     # Build the Pulse plugin and library (first time only)
#   make verify    # Verify the BPFStar library
#   make examples  # Verify the examples
#   make clean     # Clean BPFStar build artefacts
#
# Prerequisites:
#   - fstar.exe on PATH (or set FSTAR_EXE)
#   - The fstar/ submodule initialised (git submodule update --init)

PULSE_ROOT := $(CURDIR)/fstar/pulse
FSTAR_EXE ?= fstar.exe

include $(PULSE_ROOT)/mk/common.mk

.DEFAULT_GOAL := verify

# Build Pulse (only needed once, or after fstar/ submodule updates)
.PHONY: pulse
pulse:
	$(MAKE) -C $(PULSE_ROOT)

# Verify the BPFStar library
.PHONY: verify
verify:
	$(MAKE) -C lib PULSE_ROOT=$(PULSE_ROOT)

# Verify the examples
.PHONY: examples
examples: verify
	$(MAKE) -C examples/minimal PULSE_ROOT=$(PULSE_ROOT)

# Clean BPFStar build artefacts (does not clean fstar/)
.PHONY: clean
clean:
	$(MAKE) -C lib clean
	$(MAKE) -C examples/minimal clean

# Deep clean: also clean fstar/pulse
.PHONY: distclean
distclean: clean
	$(MAKE) -C $(PULSE_ROOT) clean
