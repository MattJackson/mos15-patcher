#!/bin/bash
# Build mos15-patcher.kext (cross-compiled on ARM Mac for x86_64 kernel).
set -e
cd "$(dirname "$0")"

KERN_SDK="${KERN_SDK:-../docker-macos/kexts/deps/MacKernelSDK}"
[ -d "$KERN_SDK" ] || { echo "MacKernelSDK not found at $KERN_SDK — set KERN_SDK env var"; exit 1; }

OUT="build/mos15-patcher.kext/Contents/MacOS/mos15-patcher"
mkdir -p "$(dirname "$OUT")"
cp Info.plist build/mos15-patcher.kext/Contents/Info.plist

CXX="xcrun -sdk macosx clang++"
CC="xcrun -sdk macosx clang"

CXXFLAGS=(
    -target x86_64-apple-macos10.15 -arch x86_64 -std=c++17
    -fno-rtti -fno-exceptions -fno-builtin -fno-common -fno-stack-protector
    -mkernel -nostdlib -nostdinc -nostdinc++
    -DKERNEL -DKERNEL_PRIVATE
    -I"$KERN_SDK/Headers"
    -Iinclude -Isrc -w
)
CFLAGS=(
    -target x86_64-apple-macos10.15 -arch x86_64
    -fno-builtin -fno-common -fno-stack-protector -mkernel -nostdlib -nostdinc
    -DKERNEL -DKERNEL_PRIVATE -I"$KERN_SDK/Headers" -w
)

echo "=== compile ==="
$CC  "${CFLAGS[@]}"   -c src/kmod_info.c -o build/kmod_info.o
$CXX "${CXXFLAGS[@]}" -c src/macho.cpp   -o build/macho.o
$CXX "${CXXFLAGS[@]}" -c src/patch.cpp   -o build/patch.o
$CXX "${CXXFLAGS[@]}" -c src/vtable.cpp  -o build/vtable.o
$CXX "${CXXFLAGS[@]}" -c src/notify.cpp  -o build/notify.o
$CXX "${CXXFLAGS[@]}" -c src/start.cpp   -o build/start.o

echo "=== link ==="
$CXX -target x86_64-apple-macos10.15 -arch x86_64 -nostdlib \
    -Xlinker -kext -Xlinker -no_data_const -Xlinker -no_source_version \
    -L"$KERN_SDK/Library/x86_64" \
    build/kmod_info.o build/macho.o build/patch.o build/vtable.o build/notify.o build/start.o -lkmod \
    -o "$OUT"

echo "=== done ==="
file "$OUT"
nm "$OUT" | grep -E "mp_route|mp_start|kmod_info" | head -10
