{{- define "soctalk-tenant.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
soctalk.io/tenant-id: {{ .Values.tenant.id | quote }}
soctalk.io/tenant-slug: {{ .Values.tenant.slug | quote }}
soctalk.io/mssp-id: {{ .Values.tenant.msspId | quote }}
soctalk.io/install-id: {{ .Values.tenant.installId | quote }}
{{- end -}}

{{- define "soctalk-tenant.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
The tenant namespace name. Helm is installed into this namespace: the
SocTalk controller creates it first with required labels.
*/}}
{{- define "soctalk-tenant.namespace" -}}
{{- printf "tenant-%s" .Values.tenant.slug -}}
{{- end -}}
