# Retro SSE compatibility layer v0.3

Experimental x86-64 compatibility layer for RetroBrunch/Pineview systems that lack SSE4.1/SSE4.2/POPCNT.

## v0.3 goals

- Keep the proven SIGILL emulation path from v0.1.
- Fix preload for secure-execution processes: install in `/lib64`, preload by basename, set mode 4755.
- Persist unsupported-SIGILL diagnostics when possible, so one boot can leave useful evidence without filming every line.
- Add more common x86-64-v2-era instructions.

Current emulation includes PINSRB, PINSRD/Q, PEXTRB, PEXTRD/Q, PTEST, PMULDQ, PCMPEQQ,
PACKUSDW, PCMPGTQ, PMINSB/PMINSD/PMINUW/PMINUD, PMAXSB/PMAXSD/PMAXUW/PMAXUD,
PMULLD, BLENDPS/BLENDPD/PBLENDW, POPCNT, and CRC32/CRC32C instruction forms.

Unknown SIGILLs are logged with PID, process name, RIP, RFLAGS, and 15 opcode bytes, then the process exits 132.
The layer does **not** blindly skip unknown instructions because that would corrupt program state.

Preferred persistent log target:
`/mnt/stateful_partition/unencrypted/retro-sse.log`
Fallbacks: `/var/log/retro-sse.log`, then `/tmp/retro-sse.log`.

## Install to an offline ChromeOS ROOT-A

```sh
mount /dev/sda3 /mnt/roota
./install-sseemu.sh /mnt/roota ./libretro_sse.so
cat /mnt/roota/etc/ld.so.preload
ls -l /mnt/roota/lib64/libretro_sse.so
sync
umount /mnt/roota
```

Expected preload line:
`libretro_sse.so`

Expected library permissions begin with `-rwsr-xr-x` (4755). The setuid mode is intentional: glibc secure-execution mode ignores unsafe preload paths and only accepts preloads from standard library directories with this bit set.


## v0.3
Added full SSE4.1 PMOVSX*/PMOVZX* family (0F 38 20-25, 30-35), including PMOVSXBQ observed in ChromeOS sed on Pineview.


## v0.4

- Kept the emulator handler installed when ChromeOS tried to replace SIGILL handling.
- This proved why PID 1 previously died, but hard-blocking every SIGILL registration could interfere with normal ChromeOS behavior.

## v0.7

- Replaces hard blocking with **SIGILL handler chaining**.
- ChromeOS may register its own SIGILL handler and receives normal `sigaction()` semantics.
- Retro SSE remains the kernel-visible first handler.
- Supported SSE4/POPCNT/CRC32 instructions are emulated first.
- Unknown SIGILLs are forwarded to the ChromeOS downstream handler.
- If a downstream handler returns without advancing RIP, Retro SSE terminates the process instead of looping forever on the same illegal instruction.
- Registration logging is rate-limited to reduce early-boot log spam.
