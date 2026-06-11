module github.com/soctalk/soctalk/setup-wizard

go 1.22

// v3 design (post-codex): wizard is a thin values/secret generator, not
// an installer. We do NOT need the helm SDK or kubernetes client; the
// existing soctalk-firstboot.sh script reads /etc/soctalk/values.yaml +
// /etc/soctalk/llm.key and runs helm install on its own. Only runtime
// dep we need is google/uuid for msspId/installId generation.

require github.com/google/uuid v1.6.0
