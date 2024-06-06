#!/bin/bash
#
# Test script for AES-256 Encrypted File System
# This script tests basic file system operations
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

MOUNT_POINT="/tmp/aesfs_test_$$"
AESFS_PID=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ -n "$AESFS_PID" ] && kill -0 "$AESFS_PID" 2>/dev/null; then
        fusermount -u "$MOUNT_POINT" 2>/dev/null || true
        sleep 0.5
        wait "$AESFS_PID" 2>/dev/null || true
    fi
    rmdir "$MOUNT_POINT" 2>/dev/null || true
    rm -rf "$SCRIPT_DIR/keys" 2>/dev/null || true
    echo "Cleanup complete."
}
trap cleanup EXIT

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
}

echo "=========================================="
echo " AES Encrypted File System Tests"
echo "=========================================="

# Ensure aesfs is built
if [ ! -f "$SCRIPT_DIR/aesfs" ]; then
    echo "Building aesfs..."
    make -C "$SCRIPT_DIR" || { echo "Build failed!"; exit 1; }
fi

# Create mount point
mkdir -p "$MOUNT_POINT"
echo "Mount point: $MOUNT_POINT"

# Start file system in background
echo "Starting aesfs..."
"$SCRIPT_DIR/aesfs" -f "$MOUNT_POINT" &
AESFS_PID=$!
sleep 1

# Check if aesfs is running
if ! kill -0 "$AESFS_PID" 2>/dev/null; then
    echo -e "${RED}Failed to start aesfs${NC}"
    exit 1
fi
echo -e "${GREEN}aesfs started (PID: $AESFS_PID)${NC}\n"

# ==================== TESTS ====================

echo "--- Test 1: Create and read file ---"
echo "Hello, World!" > "$MOUNT_POINT/test1.txt"
CONTENT=$(cat "$MOUNT_POINT/test1.txt")
if [ "$CONTENT" = "Hello, World!" ]; then
    pass "File created and read correctly"
else
    fail "File content mismatch: got '$CONTENT'"
fi

echo "--- Test 2: Key file generation ---"
if [ -f "$SCRIPT_DIR/keys/test1.txt.key" ]; then
    KEY_SIZE=$(stat -c%s "$SCRIPT_DIR/keys/test1.txt.key")
    if [ "$KEY_SIZE" -eq 32 ]; then
        pass "Key file generated with correct size (32 bytes)"
    else
        fail "Key file size incorrect: $KEY_SIZE bytes"
    fi
else
    fail "Key file not generated"
fi

echo "--- Test 3: Multiple files ---"
echo "File A" > "$MOUNT_POINT/fileA.txt"
echo "File B" > "$MOUNT_POINT/fileB.txt"
CONTENT_A=$(cat "$MOUNT_POINT/fileA.txt")
CONTENT_B=$(cat "$MOUNT_POINT/fileB.txt")
if [ "$CONTENT_A" = "File A" ] && [ "$CONTENT_B" = "File B" ]; then
    pass "Multiple files work correctly"
else
    fail "Multiple files content mismatch"
fi

echo "--- Test 4: List directory ---"
FILES=$(ls "$MOUNT_POINT" | sort | tr '\n' ' ')
if [[ "$FILES" == *"fileA.txt"* ]] && [[ "$FILES" == *"fileB.txt"* ]] && [[ "$FILES" == *"test1.txt"* ]]; then
    pass "Directory listing correct"
else
    fail "Directory listing incorrect: $FILES"
fi

echo "--- Test 5: File append ---"
echo "Line 1" > "$MOUNT_POINT/append.txt"
echo "Line 2" >> "$MOUNT_POINT/append.txt"
LINES=$(cat "$MOUNT_POINT/append.txt")
if [[ "$LINES" == *"Line 1"* ]] && [[ "$LINES" == *"Line 2"* ]]; then
    pass "File append works"
else
    fail "File append failed: $LINES"
fi

echo "--- Test 6: Delete file ---"
rm "$MOUNT_POINT/test1.txt"
if [ ! -f "$MOUNT_POINT/test1.txt" ]; then
    pass "File deleted"
else
    fail "File still exists after deletion"
fi

echo "--- Test 7: Key file cleanup on delete ---"
if [ ! -f "$SCRIPT_DIR/keys/test1.txt.key" ]; then
    pass "Key file removed after file deletion"
else
    fail "Key file still exists after file deletion"
fi

echo "--- Test 8: Create directory ---"
mkdir "$MOUNT_POINT/subdir"
if [ -d "$MOUNT_POINT/subdir" ]; then
    pass "Directory created"
else
    fail "Directory not created"
fi

echo "--- Test 9: Create file in subdirectory ---"
echo "Nested file" > "$MOUNT_POINT/subdir/nested.txt"
NESTED=$(cat "$MOUNT_POINT/subdir/nested.txt")
if [ "$NESTED" = "Nested file" ]; then
    pass "File in subdirectory works"
else
    fail "Nested file content mismatch"
fi

echo "--- Test 10: Remove directory ---"
rm "$MOUNT_POINT/subdir/nested.txt"
rmdir "$MOUNT_POINT/subdir"
if [ ! -d "$MOUNT_POINT/subdir" ]; then
    pass "Directory removed"
else
    fail "Directory still exists"
fi

# ==================== SUMMARY ====================

echo ""
echo "=========================================="
echo " Test Results"
echo "=========================================="
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "\n${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "\n${RED}Some tests failed.${NC}"
    exit 1
fi
