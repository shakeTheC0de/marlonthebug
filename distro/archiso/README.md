# MarlonTheBug Arch Linux live images

Two independent `archiso` profiles:

| ISO | Purpose | Desktop | Network | Persistence |
|---|---|---|---|---|
| `mtb-privacy` | Tails-like privacy workstation | Xfce | Tor-only, default-deny firewall | None |
| `mtb-audit` | Auditing / CPTS / CTF workstation | Xfce + KDE Plasma (SDDM) | Direct | None in live; install to disk with `archinstall` |

They deliberately do **not** share a session. The privacy image has no panel,
no Metasploit and no offensive tooling. The audit image warns that it has no
anonymity.

## Repository layout

```text
distro/archiso/
├── build.sh                 # assembles a profile and runs mkarchiso
├── common/
│   ├── packages.base.x86_64 # packages shared by both images
│   ├── pacman.conf
│   ├── bootstrap_packages
│   ├── boot/syslinux/       # shared splash screen
│   └── airootfs/            # shared files, scripts and services
├── privacy/
│   ├── profiledef.sh
│   ├── packages.x86_64
│   ├── boot/                # BIOS + UEFI boot entries
│   └── airootfs/            # Tor, nftables, LightDM, privacy scripts
└── audit/
    ├── profiledef.sh
    ├── packages.x86_64
    ├── boot/
    └── airootfs/            # panel, SDDM, audit warning, tools
```

`build.sh` copies `common/airootfs`, overlays the variant, concatenates the
package lists and calls `mkarchiso`. The assembled profile lives in
`distro/archiso/.build/` and is disposable.

## How an archiso image boots

1. The firmware (BIOS or UEFI) loads the bootloader from the ISO.
2. The kernel and the archiso initramfs start.
3. The initramfs finds the ISO by label/UUID, mounts `airootfs.sfs`
   (squashfs, read-only) and creates an **overlayfs** with a tmpfs upper layer.
4. systemd starts from the overlay. Writes go to RAM (`cow_spacesize`), not to
   the USB stick.
5. The display manager starts the desktop. On power-off the tmpfs disappears.

This is why the privacy image is amnesic by default: there is no persistence
partition and no write-back to the USB.

## Build requirements

- Linux x86_64. An Arch host is ideal because `mkarchiso` and `archiso` are
  native packages.
- Or Docker/podman on any Linux host. The script runs `archlinux:latest`
  with `--privileged` because archiso mounts `/proc`, `/sys`, `/dev` and uses
  `arch-chroot`.
- About 15-25 GB free disk for a full build, plus network access.
- **Un host que no sea Linux no es compatible para construir la ISO.** Usa
  Docker en una máquina Linux, una VM Arch o GitHub Actions.

### Arch host

```bash
sudo pacman -S --needed archiso rsync curl
./distro/archiso/build.sh --profile all
```

### Docker / podman on Linux

```bash
./distro/archiso/build.sh --profile all --engine docker
# or
./distro/archiso/build.sh --profile privacy --engine podman
```

The container path is mounted at `/work`; ISOs appear in
`distro/archiso/out/` on the host.

### GitHub Actions

The workflow `.github/workflows/arch-iso.yml` builds `privacy` and `audit` in
parallel on separate runners and uploads each ISO as an artifact. Run it
manually or push a `v*` tag.

## Output

```text
distro/archiso/out/
├── mtb-privacy-YYYY.MM.DD-x86_64.iso
├── mtb-privacy-YYYY.MM.DD-x86_64.iso.sha256
├── mtb-audit-YYYY.MM.DD-x86_64.iso
└── mtb-audit-YYYY.MM.DD-x86_64.iso.sha256
```

Write the ISO to a USB stick with Etcher, `dd` or Ventoy. **The target device
is destroyed.**

```bash
# Linux: check the device name carefully (lsblk), then:
sudo dd if=distro/archiso/out/mtb-privacy-*.iso of=/dev/sdX bs=4M status=progress oflag=sync
```

Secure Boot is not signed. Disable it in the firmware or enrol your own keys
before booting the ISO.

## Testing in QEMU

BIOS:

```bash
qemu-system-x86_64 -m 4096 -enable-kvm \
  -cdrom distro/archiso/out/mtb-privacy-*.iso
```

UEFI (OVMF):

```bash
cp /usr/share/OVMF/OVMF_VARS.fd /tmp/OVMF_VARS.fd
qemu-system-x86_64 -m 4096 -enable-kvm \
  -machine q35 -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
  -drive if=pflash,format=raw,file=/tmp/OVMF_VARS.fd \
  -cdrom distro/archiso/out/mtb-privacy-*.iso
```

Para probar estas imágenes x86_64 usa un host Linux x86_64 o un USB real.

## Privacy profile

### What it enforces

- **Tor-only network**: nftables default-deny; only the `tor` user may reach
  the internet. DHCP and loopback are allowed. IPv6 is disabled by kernel
  parameter and sysctl.
- **No direct DNS**: `/etc/resolv.conf` points at public resolvers, but
  nftables blocks port 53 for every process except Tor. Applications must use
  Tor Browser, `torsocks` or another SOCKS-aware client.
- **Tor Browser bundled**: Tor Browser 16.0.1 is extracted into
  `/opt/tor-browser`; it uses the system Tor daemon
  (`TOR_SKIP_LAUNCH=1`, SOCKS `127.0.0.1:9050`). It does not download a
  browser on first boot.
- **Random hostname and machine-id per boot**: the hostname is generated in
  `mtb-privacy-init`; `/etc/machine-id` is empty in the image and systemd
  creates a fresh one at boot.
- **MAC randomization**: physical interfaces are randomized before
  NetworkManager starts; NetworkManager also uses random cloned MACs.
- **Volatile logs**: journald uses `Storage=volatile`.
- **No core dumps, no suspend/hibernate, no automatic internal-disk mounts**:
  the GPT auto-generator is masked and `udisks2` is not used.
- **No panel, no Metasploit, no offensive tooling.**

### Desktop

LightDM autologins as `mtb` (password empty; `sudo` is passwordless for the
live session). Xfce starts, waits for Tor bootstrap and opens Tor Browser.
Shortcuts on the desktop:

- **Tor Browser**
- **Comprobar privacidad** (`mtb-privacy-check`)

Useful commands:

```bash
mtb-tor-status
mtb-privacy-check
sudo nft list ruleset
journalctl -u tor -b
journalctl -u mtb-privacy-init -b
```

### Known limitations

- This is **not Tails** and has not received a Tails-level audit.
- MAC spoofing is best-effort; some drivers/firmware ignore it.
- Captive portals are not supported by design (HTTP is blocked). Use a phone
  hotspot or a network without a portal. An explicit "unsafe browser" mode can
  be added later.
- Tor protects the network path, not a compromised browser, firmware,
  hardware, or a user who logs into identifying accounts.
- The ISO is pinned to a Tor Browser version; rebuild to update it.
- No persistence: notes and downloads disappear at shutdown.

## Audit profile

### What it includes

- SDDM with **Xfce** and **KDE Plasma** sessions.
- MarlonTheBug panel as a systemd service on `127.0.0.1:8765`, running as
  `mtb`, with local tool execution and the panel token.
- Xfce + KDE desktop applications, Firefox, KeePassXC, CherryTree, Flameshot.
- Official Arch packages: `nmap`, `masscan`, `sqlmap`, `nikto`, `gobuster`,
  `hydra`, `hashcat`, `john`, `wireshark`, `tcpdump`, `openvpn`,
  `proxychains-ng`, `socat`, `aircrack-ng`, `bettercap`, `impacket`,
  `metasploit`, `archinstall`, `gparted`, `testdisk`, `ddrescue`.
- Best-effort Go/Ruby tools: `ffuf`, `nuclei`, `httpx`, `chisel`, `kerbrute`,
  `whatweb`. Their presence is recorded in `/etc/mtb-tools.txt`.
- `archinstall` for installing Arch to disk. Choose Xfce, KDE or another
  desktop in the installer's profile menu.

### Login and panel

- User: `mtb`
- Password: `mtb` (live lab only; change it if you install to disk)
- Panel: `http://127.0.0.1:8765/` (opens automatically at login)
- Data: `~/.local/share/MarlonTheBug`
- Config: `~/.config/MarlonTheBug/config.yaml`

The default panel config uses the `local` backend and disables exploitation
until you explicitly enable it per project. Only use it against systems you
own or have written authorization to test.

### Install to disk

Use the **Instalar en disco** desktop shortcut, or run:

```bash
sudo archinstall
```

`archinstall` installs a stock Arch system with the desktop you choose. The
MarlonTheBug panel is **not** copied automatically to the installed system yet;
that requires a custom installer/profile and is the next milestone.

## Learning path inside this directory

1. **Packages**: edit `common/packages.base.x86_64` or a variant list, rebuild,
   and observe the size change.
2. **airootfs**: every file under `airootfs/` is copied into the live root.
   Add a script, a service or an Xfce autostart entry.
3. **systemd**: enable a unit in `customize_airootfs.sh` and inspect it with
   `systemctl status`.
4. **Boot**: edit `boot/syslinux/syslinux.cfg` and the systemd-boot entries;
   test BIOS and UEFI separately.
5. **Firewall**: change the nftables template, rebuild, and run
   `mtb-privacy-check`.
6. **Tor**: inspect `journalctl -u tor -b` and the bootstrap messages.
7. **Installer**: study `archinstall` profiles and later replace it with a
   custom Calamares/archinstall configuration.

## Troubleshooting

- **Build fails in pacstrap**: check the package name against
  `https://archlinux.org/packages/`; a missing package stops the whole build.
- **`mkarchiso` cannot mount**: run on Linux with root/sudo, or use
  `--engine docker` with `--privileged`.
- **No network in the live image**: `systemctl status NetworkManager`, then
  `nmcli device wifi list`. Privacy mode blocks direct traffic by design;
  check `systemctl status nftables` and `mtb-tor-status`.
- **Tor does not bootstrap**: check the clock (`date -u`), the network, and
  `journalctl -u tor -b`. Some networks block Tor; bridges are not configured
  in this MVP.
- **Tor Browser does not open**: `ls -l /opt/tor-browser/Browser/start-tor-browser`,
  then run `/usr/local/bin/mtb-tor-browser` from a terminal.
- **Audit panel does not start**: `systemctl status marlonthebug`,
  `journalctl -u marlonthebug -n 100`.
- **KDE/Xfce session missing**: check the SDDM session menu; both desktops are
  installed in the audit image.

## Next milestones

- Test both ISOs on real UEFI/BIOS hardware and Wi-Fi.
- Add Tor bridges/obfs4 and an explicit unsafe-browser mode for captive portals.
- Add a persistent encrypted volume for the audit image (not privacy).
- Build a custom installer that preserves the panel and the MarlonTheBug
  configuration on disk.
- Replace `archinstall` with a branded Calamares or a pinned archinstall JSON
  profile.
- Design the final branding (GRUB/systemd-boot, Plymouth, LightDM/SDDM, Xfce,
  icons, terminal, welcome app).
