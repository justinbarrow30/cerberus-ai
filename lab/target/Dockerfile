# A realistic "endpoint": an SSH server monitored by a real Wazuh agent.
# The agent forwards /var/log/auth.log to the Wazuh manager, so brute-force
# attempts against sshd become genuine Wazuh alerts (rules 5710/5716/5720).
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV WAZUH_MANAGER=wazuh.manager

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg2 lsb-release openssh-server rsyslog ca-certificates \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent=4.9.2-1 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
