#!/bin/bash
# Start the web + SSH services Nessus will probe, enroll the Wazuh agent, and
# keep the container alive tailing the agent log.
set -e

nginx
mkdir -p /run/sshd && /usr/sbin/sshd

echo "waiting for wazuh-manager enrollment port (1515)..."
for i in $(seq 1 60); do
  if (echo > /dev/tcp/wazuh-manager/1515) 2>/dev/null; then
    echo "wazuh-manager reachable"; break
  fi
  sleep 5
done

# Auto-enrolls via the <enrollment> block in ossec.conf, then connects on 1514.
/var/ossec/bin/wazuh-control start || true
sleep 3

# Warm the access log so monitoring has a baseline line.
curl -s localhost/ >/dev/null 2>&1 || true
echo "target ready (nginx:80, sshd:22, agent -> wazuh-manager)"

exec tail -F /var/ossec/logs/ossec.log
