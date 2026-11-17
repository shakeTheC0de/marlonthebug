# MarlonTheBug shell helpers.
# Keep this file free of secrets: it is world-readable.

if [ -f /etc/mtb-variant ]; then
    case "$(cat /etc/mtb-variant 2>/dev/null)" in
        privacy)
            alias tor-status='mtb-tor-status'
            alias privacy-check='mtb-privacy-check'
            ;;
        audit)
            alias panel='mtb-open-panel'
            alias audit-warning='mtb-audit-warning'
            ;;
    esac
fi
