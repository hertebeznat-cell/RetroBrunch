CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Werror -fPIC -fno-tree-vectorize \
	-march=x86-64 -mtune=generic -mno-sse3 -mno-ssse3 \
	-mno-sse4.1 -mno-sse4.2 -mno-avx -mno-avx2
LDFLAGS ?= -shared

all: libretro_sse.so

libretro_sse.so: sseemu.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

check: libretro_sse.so
	@echo "Dynamic dependencies:"
	@readelf -d libretro_sse.so | grep NEEDED || true
	@echo "Checking emulator binary for unsupported ISA..."
	@if objdump -d -M intel libretro_sse.so | grep -E '\b(pinsrb|pinsrd|pinsrq|pextrb|pextrd|pextrq|pminud|pmaxud|ptest|pmulld|pcmpistri|pcmpestri|crc32|popcnt|avx|v[a-z0-9]+)\b'; then \
		echo "ERROR: unsupported instruction found in libretro_sse.so"; exit 1; \
	fi

clean:
	rm -f libretro_sse.so
