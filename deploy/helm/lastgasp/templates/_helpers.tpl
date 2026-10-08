{{- define "lastgasp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "lastgasp.fullname" -}}
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

{{- define "lastgasp.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "lastgasp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels of one component, called with (dict "ctx" $ "component" "server"). */}}
{{- define "lastgasp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lastgasp.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "lastgasp.keySecretName" -}}
{{- default (printf "%s-key" (include "lastgasp.fullname" .)) .Values.key.existingSecret }}
{{- end }}

{{/* Address the agents send to: the value, or the in-cluster UDP service. */}}
{{- define "lastgasp.agentServer" -}}
{{- if .Values.agent.server }}
{{- .Values.agent.server }}
{{- else if .Values.server.enabled }}
{{- printf "%s-udp.%s.svc.%s.:%d" (include "lastgasp.fullname" .) .Release.Namespace .Values.clusterDomain (int .Values.server.service.udp.port) }}
{{- else }}
{{- fail "agent.server is required when server.enabled is false" }}
{{- end }}
{{- end }}

{{- define "lastgasp.image" -}}
{{- printf "%s:%s" .image.repository (default .ctx.Chart.AppVersion .image.tag) }}
{{- end }}
