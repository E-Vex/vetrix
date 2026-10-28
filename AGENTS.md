# Vetrix - Project Guide

## Overview

Vetrix is a zero-dependency packet analyzer written in C from scratch.
Currently supports pcap files with SLL2 (Linux cooked v2) link layer,
decoding IPv4 network layer and TCP/UDP transport layer.

## Build Commands

| Command | Description |
|---------|-------------|
| `make` | Debug build (default): -O0, symbols, ASan/UBSan |
| `make release` | Optimized build, no sanitizers |
| `make debug` | Explicit debug build |
| `make run ARGS="-r file.pcap -c 10"` | Build and run with arguments |
| `make clean` | Remove build/ and bin/ |
| `make rebuild` | Clean then build |
| `make NO_COLOR=1` | Disable ANSI colors |

## CLI Usage

```
./bin/vetrix -r <file.pcap> [-c <packets_to_read>] [-h]
```

- `-r`: Path to pcap file (required)
- `-c`: Number of packets to process (default: all)
- `-h`: Show help

## Source Layout

```
src/
  main.c              # Entry point: CLI, file open, global header, packet loop
  cli/cli.c           # Argument parsing (getopt)
  cli/cli.h
  file_io.c           # File open, validation
  file_io.h
  file_info.h         # file_info_t struct
  display.c           # Pretty-printing of headers and payload
  display.h
  endian.c            # Byte swapping, endianness detection
  endian.h
  protocols.h         # PCAP/SLL2/IPv4/TCP/UDP structs, magic numbers
  packet_reader.c     # Per-packet loop: header + link/network/transport dispatch
  packet_reader.h
  protocol_swap.c     # Per-field byte swap for each protocol header
  protocol_swap.h
  packet_context.h    # Shared parsing context (FILE*, remaining, endianness)
  protocol_parser/
    protocol_parser.h # Umbrella header for all layers
    packet_context.h
    data_link_layer.c # SLL2 header parsing
    data_link_layer.h
    network_layer.c   # IPv4 header parsing, TCP/UDP dispatch
    network_layer.h
    transport_layer.c # TCP and UDP header parsing
    transport_layer.h
    payload_handler.c # (unused placeholder)
    payload_handler.h
scripts/build/
  banner.sh           # ASCII banner + Makefile version
  summary.sh          # Build configuration table
  progress.sh         # Per-file compile progress with flock counter
```

## Key Design Notes

- Endianness is detected once from the pcap magic number, before the packet loop
- The pcap file is opened once in `main`, validated, and the same `FILE*` is used throughout
- All protocol structs use `__attribute__((packed))` for on-disk layout matching
- Byte swapping uses `offsetof`-based field descriptors for maintainability
- Debug builds use AddressSanitizer and UndefinedBehaviorSanitizer

## Test File

`src/test.pcap` - Sample pcap file with SLL2-encapsulated TCP traffic for manual testing.