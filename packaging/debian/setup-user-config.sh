#!/bin/sh
# Initialise ~/.reticulum/config for the calling user so that
# Python-Reticulum tools (rnstatus, rncp, Sideband, Nomadnet, …) find
# the lnsd shared-instance socket.
#
# Python's RNS.Reticulum() always boots its own instance and requires
# a writable configdir of its own — it cannot share /etc/reticulum
# with the daemon. The shared-instance hand-off works through a
# matching `instance_name` (both sides resolve the same abstract
# Unix socket \0rns/<instance_name>).
#
# This script is idempotent and never overwrites a user-modified
# config: if ~/.reticulum/config already exists, it only reports
# whether the `instance_name` matches the daemon's, and asks the user
# to edit by hand if not.
#
# Run as the user who will use the Python tools, NOT as root:
#   /usr/share/leviculum/setup-user-config.sh

set -eu

DAEMON_CONFIG="/etc/reticulum/config"
USER_CONFIG_DIR="${HOME}/.reticulum"
USER_CONFIG="${USER_CONFIG_DIR}/config"

if [ "$(id -u)" = "0" ]; then
    echo "error: run this script as the *user*, not as root." >&2
    echo "       (Python clients write into the calling user's \$HOME.)" >&2
    exit 1
fi

# Read the daemon's instance_name from /etc/reticulum/config so the
# user-side config matches whatever the operator picked.
daemon_instance="default"
if [ -r "${DAEMON_CONFIG}" ]; then
    extracted=$(awk '
        /^[[:space:]]*\[/ { in_reticulum = ($0 ~ /^[[:space:]]*\[reticulum\]/); next }
        in_reticulum && /^[[:space:]]*instance_name[[:space:]]*=/ {
            sub(/^[[:space:]]*instance_name[[:space:]]*=[[:space:]]*/, "")
            sub(/[[:space:]]*$/, "")
            print
            exit
        }
    ' "${DAEMON_CONFIG}")
    if [ -n "${extracted}" ]; then
        daemon_instance="${extracted}"
    fi
fi

if [ -e "${USER_CONFIG}" ]; then
    user_instance=$(awk '
        /^[[:space:]]*\[/ { in_reticulum = ($0 ~ /^[[:space:]]*\[reticulum\]/); next }
        in_reticulum && /^[[:space:]]*instance_name[[:space:]]*=/ {
            sub(/^[[:space:]]*instance_name[[:space:]]*=[[:space:]]*/, "")
            sub(/[[:space:]]*$/, "")
            print
            exit
        }
    ' "${USER_CONFIG}")

    if [ -z "${user_instance}" ]; then
        echo "warning: ${USER_CONFIG} exists but has no instance_name set."
        echo "         Python tools will not find lnsd's shared-instance socket."
        echo "         Add this line under [reticulum]:"
        echo "             instance_name = ${daemon_instance}"
        exit 1
    fi

    if [ "${user_instance}" = "${daemon_instance}" ]; then
        echo "OK: ${USER_CONFIG} already targets instance_name = ${daemon_instance}."
        exit 0
    fi

    echo "warning: ${USER_CONFIG} sets instance_name = ${user_instance},"
    echo "         but lnsd uses instance_name = ${daemon_instance}."
    echo "         Python tools will start their own standalone instance"
    echo "         instead of reaching the daemon. Edit the file and set:"
    echo "             instance_name = ${daemon_instance}"
    exit 1
fi

# Fresh install: write a minimal config that connects to lnsd.
mkdir -p "${USER_CONFIG_DIR}"
cat >"${USER_CONFIG}" <<EOF
# Per-user Reticulum config for Python clients (rnstatus, rncp,
# Sideband, Nomadnet, …). The matching instance_name lets these
# tools attach to lnsd's shared-instance socket instead of bringing
# up their own standalone Reticulum instance.

[reticulum]
share_instance = Yes
instance_name = ${daemon_instance}

[logging]
loglevel = 4

[interfaces]
EOF

echo "Wrote ${USER_CONFIG} (instance_name = ${daemon_instance})."
echo "Python clients (rnstatus, rncp, …) will now reach lnsd via the"
echo "shared-instance socket. No further setup needed."
