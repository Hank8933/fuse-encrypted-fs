# AES-256 Encrypted In-Memory File System (FUSE)
#
# Prerequisites:
#   sudo apt-get install build-essential libfuse-dev libssl-dev pkg-config
#
# Build: make
# Debug: make debug (enables DEBUG_PRINT macros)
# Clean: make clean

CC = gcc
CFLAGS = -Wall -Wextra -O2

# Try pkg-config first, fall back to manual flags
FUSE_CFLAGS := $(shell pkg-config --cflags fuse 2>/dev/null || echo "-D_FILE_OFFSET_BITS=64 -I/usr/include/fuse")
FUSE_LIBS := $(shell pkg-config --libs fuse 2>/dev/null || echo "-lfuse -pthread")

CFLAGS += $(FUSE_CFLAGS)
LIBS = $(FUSE_LIBS) -lssl -lcrypto

TARGET = aesfs

.PHONY: all debug clean

all: $(TARGET)

$(TARGET): aesfs.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

debug: CFLAGS += -DDEBUG -g -O0
debug: clean $(TARGET)

clean:
	rm -f $(TARGET)

