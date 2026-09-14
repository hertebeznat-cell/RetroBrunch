# Retro SSE compatibility layer v0.2

Experimental x86-64 compatibility layer for RetroBrunch/Pineview systems that lack SSE4.1/SSE4.2/POPCNT.

## v0.2 goals

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
