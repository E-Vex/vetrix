# Vetrix build system
#
# Layout:
#   src/                     core (main, file_io, packet_reader, display, endian, protocol_swap)
#   src/cli/                 argument parsing
#   src/protocol_parser/     layered decoding (data_link / network / transport / payload_handler)
#   scripts/build/           banner / summary / progress helpers used by this Makefile
#
# Usage:
#   make               debug build (default): -O0, symbols, ASan/UBSan
#   make release       optimized build, no sanitizers
#   make debug         explicit debug build
#   make run ARGS="test.pcap"
#   make test           run on src/test.pcap (10 packets)
#   make clean
#   make rebuild
#   make NO_COLOR=1    disable ANSI colors (also auto-disabled when not a TTY)

CC          := gcc
STD         := -std=c11
WARN        := -Wall -Wextra -Wpedantic
INCLUDES    := -Isrc -Isrc/cli -Isrc/protocol_parser
SRC_DIR     := src
BIN_DIR     := bin
TARGET      := $(BIN_DIR)/vetrix
MODE        ?= debug
BUILD_DIR   := build/$(MODE)
SCRIPTS_DIR := scripts/build
VERSION     := 0.1.0# TODO: bump on release

MAKEFILE_VERSION := 1.0

SRCS  := $(shell find $(SRC_DIR) -name '*.c')
OBJS  := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))
DEPS  := $(OBJS:.o=.d)
TOTAL := $(words $(OBJS))

PLATFORM := $(shell uname -s)
ARCH     := $(shell uname -m)
CC_VER   := $(shell $(CC) -dumpversion 2>/dev/null)
THREADS  := $(shell nproc 2>/dev/null || echo 1)

CFLAGS  := $(STD) $(WARN) $(INCLUDES) -MMD -MP
LDFLAGS :=

ifeq ($(MODE),debug)
    OPTFLAGS := -g3 -O0 -DDEBUG -fsanitize=address,undefined
    LDFLAGS  += -fsanitize=address,undefined
else ifeq ($(MODE),release)
    OPTFLAGS := -O2 -DNDEBUG
else
    $(error Unknown MODE '$(MODE)' - use 'debug' or 'release')
endif

CFLAGS += $(OPTFLAGS)

# MAKE_TERMOUT is set by GNU Make (>=4.1) only when its own stdout is a
# real terminal, so this stays accurate even though $(shell ...) itself
# always runs with its output piped. NO_COLOR=1 forces it off; passing
# VX_COLOR=1/0 on the command line overrides both (make gives command
# line vars priority automatically).
NO_COLOR ?= 0
ifeq ($(NO_COLOR),1)
    VX_COLOR := 0
else ifneq ($(MAKE_TERMOUT),)
    VX_COLOR := 1
else
    VX_COLOR := 0
endif

export VX_COLOR
export VX_CC             := $(CC)
export VX_CFLAGS         := $(CFLAGS)
export VX_TOTAL          := $(TOTAL)
export VX_PROGRESS_DIR   := $(BUILD_DIR)/.progress
export VX_PLATFORM       := $(PLATFORM)
export VX_ARCH           := $(ARCH)
export VX_CC_DISPLAY     := $(CC) ($(CC_VER))
export VX_MODE           := $(MODE)
export VX_THREADS        := $(THREADS)
export VX_STD            := $(STD)
export VX_WARN           := $(WARN)
export VX_OPTFLAGS       := $(OPTFLAGS)
export VX_CFLAGS_DISPLAY := $(CFLAGS)
export VX_LDFLAGS_DISPLAY:= $(if $(strip $(LDFLAGS)),$(LDFLAGS),(none))
export VX_VERSION        := $(VERSION)
export VX_MAKEFILE_VERSION := $(MAKEFILE_VERSION)

.PHONY: all debug release build run test clean rebuild

all: build

debug:
	@$(MAKE) --no-print-directory MODE=debug all

release:
	@$(MAKE) --no-print-directory MODE=release all

# The header (banner + config table) is printed by this, the *outer*,
# serial make invocation. It then re-invokes make -jN as a sub-make to
# actually compile, so the header can never get interleaved with
# parallel compile output.
build:
	@bash $(SCRIPTS_DIR)/banner.sh
	@bash $(SCRIPTS_DIR)/summary.sh
	@rm -rf $(VX_PROGRESS_DIR)
	@+$(MAKE) -s --no-print-directory MODE=$(MODE) -j$(THREADS) $(TARGET)

$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo " Linking  $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo " Done -> $@"
	@echo

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	@bash $(SCRIPTS_DIR)/progress.sh $< $@

$(BIN_DIR) $(BUILD_DIR):
	@mkdir -p $@

run: $(TARGET)
	./$(TARGET) $(ARGS)

test: $(TARGET)
	@echo "Running vetrix on src/test.pcap (10 packets)"
	@./$(TARGET) -r src/test.pcap -c 10

clean:
	rm -rf build $(BIN_DIR)

rebuild: clean all

-include $(DEPS)
