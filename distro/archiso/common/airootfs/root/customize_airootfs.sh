#!/usr/bin/env bash
# Shared post-install customization for both archiso profiles.
# archiso runs this inside the freshly pacstrapped chroot, with network access.
set -euo pipefail

VARIANT="$(cat /etc/mtb-variant)"
echo "[mtb] customize_airootfs: $VARIANT"

# ---------------------------------------------------------------------------
# Locales, keyboard and time zone
# ---------------------------------------------------------------------------
if [[ -f /etc/locale.gen ]]; then
    sed -i 's/^#es_ES.UTF-8 UTF-8/es_ES.UTF-8 UTF-8/' /etc/locale.gen
    sed -i 's/^#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
    locale-gen
fi

case "$VARIANT" in
    privacy) ln -sf /usr/share/zoneinfo/UTC /etc/localtime ;;
    audit)   ln -sf /usr/share/zoneinfo/Europe/Madrid /etc/localtime ;;
esac

# ---------------------------------------------------------------------------
# Live user: no password on privacy (autologin), known password on audit.
# The audit password is documented; it is a live lab, never a production host.
# ---------------------------------------------------------------------------
for group in wheel audio video storage power rfkill lp optical scanner network autologin systemd-journal; do
    getent group "$group" >/dev/null 2>&1 || groupadd -r "$group" 2>/dev/null || true
done

if ! id mtb >/dev/null 2>&1; then
    useradd -m -s /bin/bash mtb
fi
for group in wheel audio video storage power rfkill lp optical scanner network autologin systemd-journal; do
    getent group "$group" >/dev/null 2>&1 && usermod -aG "$group" mtb || true
done
cp -a /etc/skel/. /home/mtb/ 2>/dev/null || true
chown -R mtb:mtb /home/mtb
chmod 0750 /home/mtb

case "$VARIANT" in
    privacy)
        passwd -d mtb >/dev/null 2>&1 || true
        install -d -m 0750 /etc/sudoers.d
        cat >/etc/sudoers.d/10-mtb <<'EOF'
mtb ALL=(ALL:ALL) NOPASSWD: ALL
EOF
        ;;
    audit)
        echo 'mtb:mtb' | chpasswd
        install -d -m 0750 /etc/sudoers.d
        cat >/etc/sudoers.d/10-mtb <<'EOF'
%wheel ALL=(ALL:ALL) ALL
EOF
        ;;
esac
chmod 0440 /etc/sudoers.d/10-mtb
chmod +x /etc/skel/Desktop/*.desktop 2>/dev/null || true
chmod +x /home/mtb/Desktop/*.desktop 2>/dev/null || true

# ---------------------------------------------------------------------------
# Services common to both profiles
# ---------------------------------------------------------------------------
systemctl enable NetworkManager.service
systemctl enable mtb-network-prep.service
systemctl disable iwd.service 2>/dev/null || true
systemctl mask systemd-firstboot.service 2>/dev/null || true
systemctl disable getty@tty1.service 2>/dev/null || true
systemctl enable upower.service 2>/dev/null || true
systemctl set-default graphical.target

# ---------------------------------------------------------------------------
# Privacy profile
# ---------------------------------------------------------------------------
if [[ "$VARIANT" == "privacy" ]]; then
    echo "[mtb] hardening privacy profile"

    systemctl enable nftables.service
    systemctl enable tor.service
    systemctl enable mtb-privacy-init.service
    systemctl enable mtb-tordate.service
    systemctl enable lightdm.service
    systemctl enable accounts-daemon.service 2>/dev/null || true

    # Never let a direct NTP/DNS path leak. The firewall is the enforcement;
    # masking these units prevents accidental direct traffic.
    systemctl mask systemd-timesyncd.service systemd-time-wait-sync.service 2>/dev/null || true
    systemctl mask systemd-resolved.service 2>/dev/null || true

    # Do not route libc resolution through the masked resolver. Tor (uid tor)
    # may use the static upstream resolvers; every other process is blocked
    # by nftables, so direct DNS still fails closed.
    if [[ -f /etc/nsswitch.conf ]]; then
        sed -i 's/^hosts:.*/hosts: files myhostname dns/' /etc/nsswitch.conf
    fi

    # The live session must not touch internal disks automatically.
    systemctl mask udisks2.service 2>/dev/null || true

    # Resolve the Tor UID at build time so nftables can allow only that process
    # to reach the network. Numeric UIDs are stable inside this image.
    tor_uid="$(id -u tor)"
    sed "s/@TOR_UID@/${tor_uid}/g" /etc/nftables.conf.template >/etc/nftables.conf
    chmod 0644 /etc/nftables.conf
    rm -f /etc/nftables.conf.template

    update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

    # Tor Browser is bundled instead of downloaded on first use: the live
    # image must not require a direct download before Tor is available.
    if [[ -f /opt/tor-browser.tar.xz ]]; then
        mkdir -p /opt/tor-browser
        tar -xJf /opt/tor-browser.tar.xz -C /opt/tor-browser --strip-components=1
        rm -f /opt/tor-browser.tar.xz
        chown -R root:root /opt/tor-browser
        chmod -R go-w /opt/tor-browser
        chmod -R a+rX /opt/tor-browser
        chmod +x /opt/tor-browser/Browser/start-tor-browser 2>/dev/null || true
        chmod +x /opt/tor-browser/start-tor-browser.desktop 2>/dev/null || true
    fi
fi

# ---------------------------------------------------------------------------
# Audit profile
# ---------------------------------------------------------------------------
if [[ "$VARIANT" == "audit" ]]; then
    echo "[mtb] preparing audit profile"

    systemctl enable sddm.service
    systemctl enable marlonthebug.service
    systemctl enable accounts-daemon.service 2>/dev/null || true
    systemctl enable systemd-timesyncd.service 2>/dev/null || true

    # Make pacman usable immediately on the live audit image. The privacy
    # image does not expose package installation by design.
    pacman-key --init >/dev/null 2>&1 || true
    pacman-key --populate archlinux >/dev/null 2>&1 || true

    # The audit build needs DNS for pip/go/gem/git. arch-chroot normally
    # inherits the host resolver, but make it explicit if it is missing.
    if ! getent hosts pypi.org >/dev/null 2>&1; then
        rm -f /etc/resolv.conf
        cat >/etc/resolv.conf <<'EOF'
nameserver 9.9.9.9
nameserver 1.1.1.1
EOF
    fi

    # The panel runs from source so the ISO always matches the repository.
    # System Python packages provide almost all dependencies. `cvss` is the
    # only small pure-Python package not packaged by Arch; installing it
    # globally keeps the service simple and avoids a venv in the live image.
    if [[ -d /opt/marlonthebug ]]; then
        python -m pip install --break-system-packages --no-cache-dir --disable-pip-version-check cvss \
            || echo "[mtb] AVISO: no se pudo instalar cvss; el panel seguirá funcionando sin enriquecimiento CVSS." >&2
        chown -R root:root /opt/marlonthebug
        chmod -R go-w /opt/marlonthebug
        chmod -R a+rX /opt/marlonthebug
    fi

    install -d -o mtb -g mtb /home/mtb/.local/share/MarlonTheBug
    install -d -o mtb -g mtb /home/mtb/.config/MarlonTheBug

    # Go/Ruby tools that are not in the official repositories. These are
    # best-effort: a network hiccup must not invalidate the whole ISO.
    if command -v go >/dev/null 2>&1; then
        export HOME=/root
        export GOBIN=/usr/local/bin
        export CGO_ENABLED=0
        go install github.com/ffuf/ffuf/v2@latest \
            || echo "[mtb] AVISO: no se pudo instalar ffuf." >&2
        go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
            || echo "[mtb] AVISO: no se pudo instalar nuclei." >&2
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
            || echo "[mtb] AVISO: no se pudo instalar httpx." >&2
        go install github.com/jpillora/chisel@latest \
            || echo "[mtb] AVISO: no se pudo instalar chisel." >&2
        go install github.com/ropnop/kerbrute@latest \
            || echo "[mtb] AVISO: no se pudo instalar kerbrute." >&2
        go clean -modcache >/dev/null 2>&1 || true
    fi
    if command -v gem >/dev/null 2>&1; then
        gem install --no-document --bindir /usr/local/bin whatweb \
            || echo "[mtb] AVISO: no se pudo instalar whatweb." >&2
    fi

    # Commix is not in the official repositories. It is a well-known,
    # established framework used by the panel catalog; install it from source.
    if [[ ! -x /usr/local/bin/commix ]]; then
        if git clone --depth 1 https://github.com/commixproject/commix /opt/commix >/dev/null 2>&1; then
            chmod +x /opt/commix/commix.py
            ln -sf /opt/commix/commix.py /usr/local/bin/commix
        else
            echo "[mtb] AVISO: no se pudo instalar commix." >&2
        fi
    fi

    # Pre-download nuclei templates so the tool works offline after boot.
    if command -v nuclei >/dev/null 2>&1; then
        HOME=/home/mtb nuclei -update-templates -silent >/dev/null 2>&1 \
            || echo "[mtb] AVISO: no se pudieron descargar las plantillas de nuclei." >&2
        chown -R mtb:mtb /home/mtb/nuclei-templates /home/mtb/.config/nuclei 2>/dev/null || true
    fi

    {
        echo "Herramientas instaladas en la imagen MarlonTheBug Audit"
        echo "Generado: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        for tool in nmap masscan sqlmap nikto gobuster ffuf nuclei httpx whatweb hydra hashcat john tshark dumpcap chisel kerbrute msfconsole impacket-samrdump commix; do
            if command -v "$tool" >/dev/null 2>&1; then
                printf '%-12s %s\n' "$tool" "$(command -v "$tool")"
            else
                printf '%-12s NO DISPONIBLE\n' "$tool"
            fi
        done
    } >/etc/mtb-tools.txt

    # Unprivileged live user, but raw packet access for the standard tools.
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap 2>/dev/null || true
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap 2>/dev/null || true
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/masscan 2>/dev/null || true
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/bettercap 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Privacy: no stable machine-id across boots.
# systemd generates a new one from an empty /etc/machine-id at boot.
# Keep this at the very end so no later package script can repopulate it.
# ---------------------------------------------------------------------------
: >/etc/machine-id
rm -f /var/lib/dbus/machine-id
install -d /var/lib/dbus
ln -s /etc/machine-id /var/lib/dbus/machine-id

echo "[mtb] customize_airootfs: done ($VARIANT)"
