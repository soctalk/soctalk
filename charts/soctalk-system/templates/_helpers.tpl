{{/*
Common labels applied to every soctalk-system-managed resource.
*/}}
{{- define "soctalk-system.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
soctalk.io/mssp-id: {{ .Values.install.msspId | quote }}
soctalk.io/install-id: {{ .Values.install.installId | quote }}
{{- end -}}

{{/*
Selector labels for pod-targeting NetworkPolicies and Services.
*/}}
{{- define "soctalk-system.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Full image reference for a component, allowing per-component tag override.
Usage: {{ include "soctalk-system.image" (dict "global" .Values.image "component" "api") }}
*/}}
{{- define "soctalk-system.image" -}}
{{- $global := .global -}}
{{- $component := .component -}}
{{- printf "%s/soctalk-%s:%s" $global.registry $component $global.tag -}}
{{- end -}}

{{/*
Render standard Kubernetes resources fragment from values.
*/}}
{{- define "soctalk-system.resources" -}}
{{- with . -}}
resources:
  requests:
    cpu: {{ .requests.cpu | quote }}
    memory: {{ .requests.memory | quote }}
  limits:
    cpu: {{ .limits.cpu | quote }}
    memory: {{ .limits.memory | quote }}
{{- end -}}
{{- end -}}
