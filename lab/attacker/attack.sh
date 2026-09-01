#!/bin/sh
# Scripted SSH brute-force. Every failed attempt lands in the target's
# /var/log/auth.log, which the Wazuh agent forwards to the manager -> real alerts.
apk add --no-cache openssh-client sshpass >/dev/null 2>&1 || true

# Hit each host in TARGET_HOSTS. 'target' is the normal victim (establishes the
# baseline edge); 'secure-db' is the pivot — a host the attacker container should
# never touch, so reaching it is the lateral-movement signal.
TARGETS="${TARGET_HOSTS:-${TARGET_HOST:-target}}"
USERS="root admin test oracle victim ubuntu deploy"

echo "[attacker] hammering: ${TARGETS} — Ctrl-C to stop"
while true; do
    for host in $TARGETS; do
        for u in $USERS; do
            sshpass -p "wrong$(date +%s)$RANDOM" \
                ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                    -o ConnectTimeout=3 \
                    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
                    "${u}@${host}" true 2>/dev/null || true
            sleep 2
        done
    done
done
