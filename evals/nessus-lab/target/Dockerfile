# Scan target: a small host with a web server + SSH and a Wazuh agent, so a
# real Nessus scan against it produces real Wazuh alerts (web-attack bursts,
# auth probes) that the manager records to alerts.json.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive WAZUH_MANAGER=wazuh-manager

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg2 ca-certificates lsb-release procps \
        nginx openssh-server php-fpm php-cli \
    && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update && apt-get install -y wazuh-agent=4.9.2-1 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# A tiny, deliberately-probeable web surface so Nessus generates plentiful
# web-attack / 404 signatures (this is a benign authorized-scan lab target).
RUN mkdir -p /var/www/html && \
    printf '<html><body><h1>lab target</h1><a href="/login.php">login</a></body></html>\n' > /var/www/html/index.html && \
    printf '<?php echo "login"; ?>\n' > /var/www/html/login.php && \
    printf '<?php echo "search: ".($_GET["q"]??""); ?>\n' > /var/www/html/search.php

COPY ossec.conf /var/ossec/etc/ossec.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /run/sshd

EXPOSE 80 22
ENTRYPOINT ["/entrypoint.sh"]
