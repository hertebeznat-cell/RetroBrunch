# RetroBrunch Legacy BIOS

Experimental boot mode for old x86-64 PCs without UEFI.

Initial target:
Intel Atom D525
Intel GMA 3150
Legacy BIOS

Boot chain:

BIOS
 -> MBR boot code
 -> Syslinux
 -> RetroBrunch kernel
 -> Brunch initramfs
 -> ChromeOS ROOT-C / ROOT-A
