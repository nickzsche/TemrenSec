{{/*
Expand the name of the chart.
*/}}
{{- define "temren.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "temren.fullname" -}}
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
{{- define "temren.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "temren.labels" -}}
helm.sh/chart: {{ include "temren.chart" . }}
app.kubernetes.io/name: {{ include "temren.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for a component ("api" or "worker").
Usage: {{ include "temren.selectorLabels" (dict "root" . "component" "api") }}
*/}}
{{- define "temren.selectorLabels" -}}
app.kubernetes.io/name: {{ include "temren.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "temren.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "temren.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image tag (falls back to appVersion).
*/}}
{{- define "temren.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion }}
{{- end }}

{{/*
Full image references: <repository>-<suffix>:<tag>
*/}}
{{- define "temren.apiImage" -}}
{{- printf "%s-%s:%s" .Values.image.repository .Values.api.imageSuffix (include "temren.imageTag" .) }}
{{- end }}

{{- define "temren.workerImage" -}}
{{- printf "%s-%s:%s" .Values.image.repository .Values.worker.imageSuffix (include "temren.imageTag" .) }}
{{- end }}

{{/*
Name of the Secret holding JWT_SECRET / DATABASE_URL / REDIS_URL.
*/}}
{{- define "temren.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "temren.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Hostnames of the bundled Bitnami subcharts (their fullname is <release>-<chart>).
*/}}
{{- define "temren.postgresqlHost" -}}
{{- printf "%s-postgresql" .Release.Name }}
{{- end }}

{{- define "temren.redisHost" -}}
{{- printf "%s-redis-master" .Release.Name }}
{{- end }}

{{/*
DATABASE_URL — built from the postgresql subchart values, or config.databaseUrl for an external DB.
*/}}
{{- define "temren.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- $pw := required "postgresql.auth.password is required when postgresql.enabled=true (e.g. --set postgresql.auth.password=$(openssl rand -hex 16))" .Values.postgresql.auth.password }}
{{- printf "postgres://%s:%s@%s:5432/%s?sslmode=disable" .Values.postgresql.auth.username $pw (include "temren.postgresqlHost" .) .Values.postgresql.auth.database }}
{{- else }}
{{- required "config.databaseUrl is required when postgresql.enabled=false" .Values.config.databaseUrl }}
{{- end }}
{{- end }}

{{/*
REDIS_URL — built from the redis subchart values, or config.redisUrl for an external Redis.
*/}}
{{- define "temren.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s:6379" (include "temren.redisHost" .) }}
{{- else }}
{{- required "config.redisUrl is required when redis.enabled=false" .Values.config.redisUrl }}
{{- end }}
{{- end }}

{{/*
TEMREN_WS_REDIS — host:port of Redis for the WebSocket pub/sub bridge.
*/}}
{{- define "temren.wsRedisAddr" -}}
{{- if .Values.redis.enabled }}
{{- printf "%s:6379" (include "temren.redisHost" .) }}
{{- else if .Values.config.wsRedisAddr }}
{{- .Values.config.wsRedisAddr }}
{{- else }}
{{- .Values.config.redisUrl | trimPrefix "redis://" | trimPrefix "rediss://" }}
{{- end }}
{{- end }}
