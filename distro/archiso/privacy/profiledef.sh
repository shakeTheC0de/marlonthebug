#!/usr/bin/env bash
# shellcheck disable=SC2034

iso_name="mtb-privacy"
iso_label="MTB_PRIVACY_$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y%m)"
iso_publisher="MarlonTheBug <https://github.com/shakeTheC0de/marlonthebug>"
iso_application="MarlonTheBug Privacy Live"
iso_version="$(date --date="@${SOURCE_DATE_EPOCH:-$(date +%s)}" +%Y.%m.%d)"
install_dir="arch"
bootmodes=('bios.syslinux' 'uefi.systemd-boot')
pacman_conf="pacman.conf"
airootfs_image_type="squashfs"
airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M' '-Xdict-size' '1M')
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--auto-threads=logical' '--long' '-19')
file_permissions=(
  ["/root"]="0:0:750"
  ["/root/customize_airootfs.sh"]="0:0:755"
  ["/usr/local/bin/mtb-privacy-init"]="0:0:755"
  ["/usr/local/bin/mtb-macspoof"]="0:0:755"
  ["/usr/local/bin/mtb-tordate"]="0:0:755"
  ["/usr/local/bin/mtb-tor-status"]="0:0:755"
  ["/usr/local/bin/mtb-tor-browser"]="0:0:755"
  ["/usr/local/bin/mtb-privacy-check"]="0:0:755"
  ["/usr/local/bin/mtb-privacy-session"]="0:0:755"
  ["/usr/local/bin/mtb-network-prep"]="0:0:755"
  ["/usr/local/bin/mtb-set-wallpaper"]="0:0:755"
)
