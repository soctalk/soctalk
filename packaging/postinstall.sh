#!/bin/sh
# Post-install: a `yum/apt install soctalk` lays down the CLI + installer but
# must NOT silently stand up k3s (GitLab-omnibus pattern). Tell the operator
# the one next step.
cat <<'EOF'

SocTalk installed. Bring up the SOC stack on this host with:

    sudo soctalk install          # interactive
    sudo soctalk install --demo   # non-interactive demo (random admin password)

Then check it:  soctalk status
Docs:           https://soctalk.github.io/soctalk-docs/

EOF
exit 0
