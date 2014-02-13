#!/bin/sh
# dnssec-trigger script handling possible backup and restore of resolv.conf

SCRIPT_NAME="dnssec-trigger-resolvconf-handle.sh"
STATE_DIR="/var/run/dnssec-trigger"
RESOLV_CONF="/etc/resolv.conf"
RESOLV_CONF_BAK="$STATE_DIR/resolv.conf.bak"
NM_CONFIG="/etc/NetworkManager/NetworkManager.conf"

usage()
{
    echo
    echo "This script backs up or restores /etc/resolv.conf content"
    echo "Usage: $SCRIPT_NAME [backup|restore]"
}

# check number of arguments
if ! [ "$#" -eq 1 ]; then
    echo "ERROR: Wrong number of arguments!"
    usage
    exit 1
fi

does_nm_handle_resolv_conf()
{
    grep -x "^dns=none" $NM_CONFIG &> /dev/null
    echo "$?"
}

backup_resolv_conf()
{
    # find out if NM handles the resolv.conf
    if [ "`does_nm_handle_resolv_conf`" -eq 0 ]; then
        cp -fp $RESOLV_CONF $RESOLV_CONF_BAK
    fi
}

restore_resolv_conf()
{
    # if we have a backup and NM does not handle resolv.conf -> restore it
    if [ "`does_nm_handle_resolv_conf`" -eq 0 ] && [ -s $RESOLV_CONF_BAK ]; then
        cp -fp $RESOLV_CONF_BAK $RESOLV_CONF
    else
        # let NM rewrite the resolv.conf
        systemctl restart NetworkManager.service
    fi
}

case "$1" in
    backup)
        backup_resolv_conf
        ;;
    restore)
        restore_resolv_conf
        ;;
    *)
        echo "ERROR: Wrong argument!"
        usage
        exit 1
esac

exit 0
