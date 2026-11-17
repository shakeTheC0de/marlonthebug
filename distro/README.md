# MarlonTheBug Live images

This directory builds two USB images with **Arch Linux + archiso**:

| Image | Use | Desktop | Network |
|---|---|---|---|
| `mtb-privacy` | Private, amnesic live session | Xfce | Tor-only |
| `mtb-audit` | Auditing, CPTS and CTF | Xfce + KDE | Direct |

The detailed technical guide is in
[`archiso/README.md`](archiso/README.md). The rest of this file covers building,
flashing and the security model.

## Why Arch + archiso

- You learn the real pieces: pacman, systemd, mkinitcpio, squashfs, overlayfs,
  UEFI/BIOS boot and a minimal root filesystem.
- The build is reproducible and small enough to understand.
- LFS/BLFS is a great course but a poor daily privacy/USB system: keeping it
  patched and secure by hand is a full-time job. Use an LFS VM later if you
  want to go deeper.

## Build

### Recommended: Arch Linux host

```bash
sudo pacman -S --needed archiso rsync curl
./distro/archiso/build.sh --profile all
```

### Any Linux with Docker or podman

```bash
./distro/archiso/build.sh --profile all --engine docker
```

The container runs `archlinux:latest` with `--privileged` because archiso
needs to mount `/proc`, `/sys`, `/dev` and use `arch-chroot`.

### GitHub Actions

Run **Arch Live ISO** manually, or push a `v*` tag. It builds `privacy` and
`audit` on separate runners and uploads both ISOs as artifacts.

### macOS

macOS is **not** a reliable host for building a live ISO. Use GitHub Actions,
a Linux machine or an Arch VM. You can still write the resulting ISO to a USB
from macOS with Etcher or `dd`.

## Output

```text
distro/archiso/out/
├── mtb-privacy-YYYY.MM.DD-x86_64.iso
├── mtb-privacy-YYYY.MM.DD-x86_64.iso.sha256
├── mtb-audit-YYYY.MM.DD-x86_64.iso
└── mtb-audit-YYYY.MM.DD-x86_64.iso.sha256
```

Flash with Etcher, `dd` or Ventoy. **The target USB is destroyed.**

```bash
lsblk
sudo dd if=distro/archiso/out/mtb-privacy-*.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

Secure Boot is not signed. Disable it or enrol your own keys.

## Privacy image

- Xfce + LightDM autologin; Tor Browser 16.0.1 bundled.
- Tor-only: nftables default-deny; only the `tor` user can reach the network.
- IPv6 disabled; direct DNS blocked; MAC randomized; random hostname and
  machine-id per boot; volatile logs; no core dumps; no auto-mount of internal
  disks.
- No panel, no Metasploit, no offensive tooling, no persistence.
- Desktop shortcuts: **Tor Browser** and **Comprobar privacidad**.
- Verify with `mtb-privacy-check`, `mtb-tor-status` and
  `sudo nft list ruleset`.

This is not Tails and has not received a Tails-level audit. Captive portals are
not supported because direct HTTP is blocked; use a network without a portal or
a phone hotspot. Tor does not protect against compromised hardware, firmware,
browser exploits or identifying user behaviour.

## Audit image

- SDDM with Xfce and KDE Plasma sessions.
- MarlonTheBug panel on `127.0.0.1:8765`, running as `mtb` with local tools.
- Firefox, KeePassXC, CherryTree, Flameshot, Xfce/KDE apps.
- Official Arch tools: nmap, masscan, sqlmap, nikto, gobuster, hydra, hashcat,
  john, Wireshark, tcpdump, OpenVPN, proxychains, socat, aircrack-ng,
  bettercap, Impacket and Metasploit.
- Best-effort Go/Ruby tools: ffuf, nuclei, httpx, chisel, kerbrute, whatweb.
  See `/etc/mtb-tools.txt` in the image.
- `archinstall` for installing to disk (Xfce, KDE or another profile).

Live credentials:

```text
user: mtb
password: mtb
panel:  http://127.0.0.1:8765/
```

The audit image provides **no anonymity**. Use it only on systems you own or
have written authorization to test. The panel logs actions; exploitation is
disabled by default in the panel config until you enable it per project.

`archinstall` installs a stock Arch system; the panel is not copied to disk
automatically yet. That is the next installer milestone.

## Testing

BIOS:

```bash
qemu-system-x86_64 -m 4096 -enable-kvm \
  -cdrom distro/archiso/out/mtb-privacy-*.iso
```

UEFI (OVMF):

```bash
cp /usr/share/OVMF/OVMF_VARS.fd /tmp/OVMF_VARS.fd
qemu-system-x86_64 -m 4096 -enable-kvm -machine q35 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/tmp/OVMF_VARS.fd \
  -cdrom distro/archiso/out/mtb-audit-*.iso
```

Test on real hardware after QEMU: UEFI and BIOS, Wi-Fi, Ethernet, keyboard,
screen resolution and suspend/resume (suspend is disabled in privacy mode).

## Structure and learning

```text
distro/archiso/
├── build.sh                 # assembly + mkarchiso wrapper
├── common/                  # shared packages, configs, scripts
├── privacy/                 # Tor-only profile
└── audit/                   # panel + tools profile
```

Read [`archiso/README.md`](archiso/README.md) for the boot flow, the full
package list, hardening details, troubleshooting and learning exercises.

## Legacy Kali scaffold

`distro/build.sh`, `distro/kali-config/` and `.github/workflows/iso.yml` are the
previous Kali Live remaster. They are kept as a manual fallback while the Arch
profiles mature. The Arch images are the primary product.

## Security limits

- The privacy image is a practical, auditable baseline, not a guarantee of
  anonymity.
- The audit image contains powerful offensive tools. It is not hardened for
  hostile networks and has no anonymity.
- Do not add malware, miners, destructive payloads or unauthorized
  persistence to either image.
- Verify the SHA256 of every ISO before flashing and keep the build host
  trusted.
