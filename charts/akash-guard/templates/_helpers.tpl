{{/*
Expand the name of the chart.
*/}}
{{- define "akash-guard.name" -}}
{{- .Chart.Name }}
{{- end }}

{{/*
Full name — Release.Name if it differs from the chart name, else just the chart name.
*/}}
{{- define "akash-guard.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "akash-guard.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{ include "akash-guard.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "akash-guard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "akash-guard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: {{ include "akash-guard.name" . }}
{{- end }}

{{/*
Namespace — defaults to kube-system
*/}}
{{- define "akash-guard.namespace" -}}
{{- .Values.namespace | default "kube-system" }}
{{- end }}
