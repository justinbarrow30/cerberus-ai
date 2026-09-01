#!/bin/bash
# Start syslog + sshd, enroll the Wazuh agent, then keep the container alive.
# No `set -e`: several steps can warn non-fatally and we don't want a crash-loop.

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

mkdir -p /var/run/sshd /var/log
touch /var/log/auth.log

# --- Container-correct rsyslog config -------------------------------------
# Ubuntu's stock rsyslog leaves the /dev/log system socket OFF (it expects
# systemd's journal to forward logs) and loads imklog (needs kernel-log access).
# Neither works in a bare container, so sshd's auth events silently vanish.
# This minimal config reads /dev/log directly and routes auth -> auth.log in
# proper syslog format, which is what the Wazuh sshd decoder expects.
cat > /etc/rsyslog.conf <<'EOF'
module(load="imuxsock" SysSock.Use="on")
$FileCreateMode 0644
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none         -/var/log/syslog
EOF

pkill rsyslogd 2>/dev/null
sleep 1
rsyslogd || echo "[target] rsyslogd failed to start" >&2
sleep 1

# SSH host keys, allow password auth, add a victim account.
ssh-keygen -A 2>/dev/null || true
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
useradd -m victim 2>/dev/null || true
echo 'victim:victimpass' | chpasswd
/usr/sbin/sshd || echo "[target] sshd failed to start" >&2

# Point the agent at the manager and enroll over authd (port 1515).
sed -i "s|<address>[^<]*</address>|<address>${MANAGER}</address>|" /var/ossec/etc/ossec.conf 2>/dev/null || true

# The stock agent config in this image monitors only dpkg.log + active-responses,
# NOT /var/log/auth.log — so add it, or the SSH attack events never reach the
# manager and no brute-force alerts are ever generated.
if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    cat >> /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
</ossec_config>
EOF
fi

if ! /var/ossec/bin/agent-auth -m "${MANAGER}"; then
    echo "[target] agent enrollment failed — see lab/README.md" >&2
fi
/var/ossec/bin/wazuh-control start || echo "[target] wazuh-control start failed" >&2

echo "[target] ready: sshd up, agent enrolled to ${MANAGER}. Streaming auth.log..."
exec tail -F /var/log/auth.log
