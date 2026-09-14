# RetroBrunch SSE compatibility layer

Experimental userspace compatibility layer for old x86-64 CPUs such as Intel Atom D4xx/D5xx (Pineview) that lack SSE4.1/SSE4.2.

The library installs a `SIGILL` handler. When an unsupported instruction traps, the handler decodes the instruction, emulates its effect using baseline x86-64/SSE2-safe C code, updates the saved register/XMM state in `ucontext`, advances RIP, and resumes the process.

Initial instruction coverage:

- SSE4.1 `PINSRB`
- SSE4.1 `PINSRD` / `PINSRQ`
- SSE4.1 `PEXTRB`
- SSE4.1 `PEXTRD` / `PEXTRQ`
- SSE4.1 `PMINUD`
- SSE4.1 `PMULLD`
- SSE4.1 `PTEST`

Unknown `SIGILL` instructions are logged with RIP and the first 12 instruction bytes, then the process exits with status 132. This is intentional for the prototype: it gives the next opcode that must be implemented instead of silently corrupting state.

## Build

```sh
make
make check
```

The build deliberately disables SSE3, SSSE3, SSE4, AVX and vectorization for the compatibility library itself.

## Install into a mounted ChromeOS ROOT-A

```sh
sudo mount -o remount,rw /mnt/roota
sudo ./install-sseemu.sh /mnt/roota ./libretro_sse.so
sync
sudo mount -o remount,ro /mnt/roota
```

The installer places the library at `/lib64/libretro_sse.so` and appends it to `/etc/ld.so.preload`.

This is an experimental prototype. Keep a ROOT-A backup or recovery path. It does not yet emulate the full SSE4.1/SSE4.2 ISA and does not help static executables or faults that happen in the dynamic loader before constructors run.
