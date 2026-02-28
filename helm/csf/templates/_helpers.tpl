{{/*
Expand the name of the chart.
*/}}
{{- define "csf.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to
this (by the DNS naming spec). If release name contains the chart name it
will be used as a full name.
*/}}
{{- define "csf.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "csf.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "csf.labels" -}}
helm.sh/chart: {{ include "csf.chart" . }}
{{ include "csf.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "csf.selectorLabels" -}}
app.kubernetes.io/name: {{ include "csf.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific selector labels.
Usage: {{ include "csf.componentLabels" (dict "component" "collector" "context" .) }}
*/}}
{{- define "csf.componentLabels" -}}
app.kubernetes.io/name: {{ include "csf.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component-specific full labels (includes common labels).
Usage: {{ include "csf.componentFullLabels" (dict "component" "collector" "context" .) }}
*/}}
{{- define "csf.componentFullLabels" -}}
helm.sh/chart: {{ include "csf.chart" .context }}
{{ include "csf.componentLabels" . }}
{{- if .context.Chart.AppVersion }}
app.kubernetes.io/version: {{ .context.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .context.Release.Service }}
{{- end }}

{{/*
PostgreSQL DSN connection string.
*/}}
{{- define "csf.postgresqlDSN" -}}
postgres://{{ .Values.postgresql.credentials.username }}:{{ .Values.postgresql.credentials.password }}@{{ include "csf.fullname" . }}-postgresql:{{ .Values.postgresql.port }}/{{ .Values.postgresql.credentials.database }}?sslmode=disable
{{- end }}
