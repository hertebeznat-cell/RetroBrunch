<div align="center">

# ⚡ RetroBrunch

### Modern ChromeOS on hardware it was never meant to run on

[![Based on Brunch](https://img.shields.io/badge/Based%20on-Brunch-4285F4?logo=googlechrome&logoColor=white)](https://github.com/sebanc/brunch)
![Status](https://img.shields.io/badge/status-experimental-orange)
![Platform](https://img.shields.io/badge/platform-x86__64-lightgrey)
![Boot](https://img.shields.io/badge/boot-Legacy%20BIOS-blue)
![CPU](https://img.shields.io/badge/target-Intel%20Atom%20%2F%20Pineview-0071C5?logo=intel&logoColor=white)
![ChromeOS](https://img.shields.io/badge/ChromeOS-Rammus-34A853?logo=googlechrome&logoColor=white)
![SSE](https://img.shields.io/badge/SSE4-userspace%20emulation-purple)

<br>

**RetroBrunch** is an experimental fork of  
[sebanc/brunch](https://github.com/sebanc/brunch) focused on running recent ChromeOS builds on old x86_64 PCs.

It adds Legacy BIOS support, Pineview-specific configuration, and a userspace compatibility layer that emulates unsupported SSE4-era instructions on CPUs such as the **Intel Atom D525**.

</div>

---

## ✨ What makes RetroBrunch different?

Modern ChromeOS assumes CPU features that many older x86_64 processors simply do not have.

A typical RetroBrunch target looks like this:

```text
CPU:      Intel Atom D525 @ 1.80 GHz
Cores:    2
Threads:  4
Arch:     x86_64
SSE:      SSE / SSE2 / SSSE3
Missing:  SSE4.1 / SSE4.2 / POPCNT / AVX
GPU:      Intel GMA 3150
Firmware: Legacy BIOS
RAM:      ~4 GB
```

On hardware like this, stock ChromeOS dies very early with errors such as:

```text
invalid opcode
SIGILL
status 132
Attempted to kill init
```

RetroBrunch works around those limitations instead of giving up.

---

## 🚀 Current boot progress

<div align="center">

**Legacy BIOS → Syslinux → RetroBrunch kernel → ChromeOS userspace → ChromeOS splash screen**

</div>

Development on the current test machine has already progressed from immediate early-boot `SIGILL` failures to the **graphical ChromeOS splash screen**.

> [!IMPORTANT]
> This does **not** yet mean the device is fully supported.  
> Login, graphics stability, audio, networking, suspend and long-term reliability still need testing.

---

## 🧩 Core features

### 🖥️ Legacy BIOS boot

RetroBrunch adds a Legacy BIOS boot path using Syslinux and a GPT MBR.

```text
Legacy BIOS
    ↓
Syslinux GPT MBR
    ↓
RETROBIOS partition
    ↓
RetroBrunch kernel + initramfs
    ↓
ROOT-C
    ↓
ChromeOS ROOT-A / ROOT-B
```

---

### 🧠 Pineview profile

A dedicated `pineview` profile targets Intel Atom D4xx / D5xx generation systems.

Example:

```text
Profile:  pineview
Kernel:   6.12
GPU:      Intel GMA 3150
Boot:     Legacy BIOS
```

---

### ⚙️ SSE4 compatibility layer

RetroBrunch includes a userspace `SIGILL` compatibility layer.

When ChromeOS executes an unsupported instruction, the layer can:

1. intercept `SIGILL`
2. decode the instruction
3. emulate its behavior in software
4. update CPU / XMM state
5. continue execution

Currently covered instructions include examples such as:

| Family | Examples |
|---|---|
| Insert / extract | `PINSRB`, `PINSRD`, `PEXTRB`, `PEXTRD` |
| Integer min/max | `PMINUD`, signed/unsigned min-max variants |
| Arithmetic | `PMULLD`, `PMULDQ` |
| Testing | `PTEST` |
| Bit counting | `POPCNT` |
| CRC | `CRC32` |
| Sign extension | `PMOVSX*` |
| Zero extension | `PMOVZX*` |
| Blend / pack | selected SSE4.1 operations |

The emulator is continuously extended from **real hardware boot traces**.

---

### 🛡️ SIGILL handler protection

Some ChromeOS processes replace signal handlers after startup.

RetroBrunch v0.4 protects its `SIGILL` handler from being removed through common signal APIs.

This allows SSE emulation to remain active deeper into the ChromeOS boot process.

---

### 📝 Persistent crash logging

Unsupported instructions can be logged to:

```text
/var/log/retro-sse.log
```

Example:

```text
retro-sse v0.x: unsupported SIGILL pid=225 comm=sed
rip=0x...
bytes=66 0f 38 ...
```

That means debugging no longer depends on photographing a fast-scrolling boot console.

---

## 🧪 Tested hardware

### Lenovo C200 All-in-One

| Component | Hardware |
|---|---|
| CPU | Intel Atom D525 @ 1.80 GHz |
| Cores / Threads | 2 / 4 |
| GPU | Intel GMA 3150 |
| RAM | ~4 GB |
| Firmware | Legacy BIOS |
| Architecture | x86_64 |
| Current progress | ChromeOS splash screen |

---

## 📦 Repository structure

```text
RetroBrunch/
├── .github/
│   └── workflows/
├── legacy-bios/
├── profiles/
│   └── pineview.conf
├── retro-sse-emu/
│   ├── sseemu.c
│   ├── Makefile
│   ├── install-sseemu.sh
│   └── README.md
├── tools/
│   └── alpine-quick-setup-v2.sh
└── ...
```

---

## 🛠️ SSE emulator

Source:

```text
retro-sse-emu/
```

Build:

```bash
make
```

Output:

```text
libretro_sse.so
```

The emulator is compiled with conservative options so the compatibility layer itself does not accidentally require unsupported CPU features.

```text
-march=x86-64
-mno-sse3
-mno-ssse3
-mno-sse4.1
-mno-sse4.2
-mno-avx
-mno-avx2
-fno-tree-vectorize
```

GitHub Actions can build a Pineview-compatible artifact automatically.

---

## 🐧 Alpine rescue environment

Development currently uses Alpine Linux Live as a fast rescue / patching environment.

Typical tasks:

- mount ChromeOS partitions
- replace SSE emulator builds
- inspect logs
- patch Syslinux config
- access the machine over SSH
- test binaries directly on the Atom D525

A helper script is included:

```text
tools/alpine-quick-setup-v2.sh
```

It can set up:

- Wi-Fi
- SSH
- `util-linux`
- `unzip`
- `curl`
- persistence helpers
- offline APK packages from the Ventoy drive

---

## 🔍 Debugging settings

Current RetroBrunch debugging options include:

```text
loglevel=7
ignore_loglevel
panic=0
```

`panic=0` is intentional.

It keeps kernel panic output visible instead of immediately rebooting, which makes debugging much easier on real hardware.

---

## ⚠️ Warning

> [!WARNING]
> RetroBrunch is experimental.

It may:

- modify ChromeOS boot files
- replace or preload shared libraries
- inject compatibility code into dynamically linked processes
- break after ChromeOS updates
- fail to boot entirely

Use it only on systems you are prepared to recover or reinstall.

Back up anything important before testing.

---

## 🙏 Credits

RetroBrunch is based on the original **Brunch Framework** by  
[sebanc](https://github.com/sebanc).

Original project:

https://github.com/sebanc/brunch

RetroBrunch legacy-hardware development:

- [hertebeznat-cell](https://github.com/hertebeznat-cell)

The goal is not to replace Brunch, but to extend its usefulness to older systems that current ChromeOS can no longer execute on directly.

---

## 📜 License

RetroBrunch contains code derived from Brunch and may include components with their own licenses.

Please refer to the original Brunch repository and individual source files for applicable license terms.

---

<div align="center">

### ⚡ RetroBrunch

**Because old hardware can still be interesting.**

</div>
