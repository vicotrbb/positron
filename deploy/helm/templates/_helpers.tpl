{{- define "positron.name" -}}
{{- printf "%s-positron" .Release.Name | trunc 52 | trimSuffix "-" -}}
{{- end -}}
{{- define "positron.validate" -}}
{{- if not (has (int .Values.replicas) (list 0 1)) -}}{{ fail "standalone replicas must be 0 or 1" }}{{- end -}}
{{- if not (regexMatch "^ghcr[.]io/vicotrbb/positron@sha256:[a-f0-9]{64}$" .Values.image) -}}{{ fail "image requires an exact OCI index digest" }}{{- end -}}
{{- if lt (int .Values.terminationGracePeriodSeconds) @STOP_GRACE_SECONDS@ -}}{{ fail "termination grace must cover every native Drain deadline" }}{{- end -}}
{{- if empty .Values.storageClass -}}{{ fail "an independently qualified storageClass is required" }}{{- end -}}
{{- if empty .Values.tlsSecret -}}{{ fail "tlsSecret reference is required" }}{{- end -}}
{{- $dataClaim := printf "%s-data" (include "positron.name" .) -}}
{{- $secretsClaim := printf "%s-secrets" (include "positron.name" .) -}}
{{- $backupClaim := default (printf "%s-backups" (include "positron.name" .)) .Values.backupClaim -}}
{{- if has .Values.backupClaim (list $dataClaim $secretsClaim) -}}{{ fail "Backup Repository cannot use this instance's data or key claim" }}{{- end -}}
{{- if has .Values.operationInputsClaim (list $dataClaim $secretsClaim $backupClaim) -}}{{ fail "operation inputs require a separate explicitly provisioned claim" }}{{- end -}}
{{- if empty .Values.configuration -}}{{ fail "native TOML configuration is required" }}{{- end -}}
{{- if or (lt (int .Values.identity.uid) 1) (lt (int .Values.identity.gid) 1) -}}{{ fail "non-root numeric identity is required" }}{{- end -}}
{{- if and .Values.maintenance.enabled (ne (int .Values.replicas) 0) -}}{{ fail "stop the StatefulSet before offline maintenance" }}{{- end -}}
{{- if and .Values.maintenance.enabled (empty .Values.maintenance.args) -}}{{ fail "native maintenance arguments are required" }}{{- end -}}
{{- if .Values.maintenance.enabled -}}
{{- if not (has (first .Values.maintenance.args) (list "verify" "backup" "upgrade" "keys" "config" "doctor")) -}}{{ fail "maintenance must select a native offline operation; claim uses an attached pod" }}{{- end -}}
{{- end -}}
{{- end -}}
{{- define "positron.pod" -}}
automountServiceAccountToken: false
terminationGracePeriodSeconds: {{ .Values.terminationGracePeriodSeconds }}
securityContext:
  runAsNonRoot: true
  runAsUser: {{ .Values.identity.uid }}
  runAsGroup: {{ .Values.identity.gid }}
  fsGroup: {{ .Values.identity.gid }}
  fsGroupChangePolicy: OnRootMismatch
  seccompProfile:
    type: RuntimeDefault
initContainers:
  - name: prepare-storage
    image: {{ .Values.image | quote }}
    imagePullPolicy: IfNotPresent
    command: [/usr/bin/positron]
    args: [bootstrap, prepare-storage, --config, /etc/positron/positron.toml]
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
    resources: {{ .Values.resources | toJson }}
    volumeMounts:
      - {name: data, mountPath: /var/lib/positron}
      - {name: secrets, mountPath: /var/lib/positron-secrets}
      - {name: configuration, mountPath: /etc/positron/positron.toml, subPath: positron.toml, readOnly: true}
      - {name: runtime, mountPath: /run/positron}
containers:
  - name: positron
    image: {{ .Values.image | quote }}
    imagePullPolicy: IfNotPresent
    command: [/usr/bin/positron]
    {{- if .Values.maintenance.enabled }}
    args: {{ .Values.maintenance.args | toJson }}
    {{- else }}
    args: [serve, --init-if-empty, --config, /etc/positron/positron.toml]
    {{- end }}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: [ALL]
    resources: {{ .Values.resources | toJson }}
    {{- if not .Values.maintenance.enabled }}
    ports:
      - {name: api, containerPort: 8080}
      - {name: otlp-grpc, containerPort: 4317}
      - {name: otlp-http, containerPort: 4318}
      - {name: loki-push, containerPort: 3100}
    startupProbe:
      exec:
        command: [/usr/bin/positron, doctor, --ready, --endpoint, "127.0.0.1:13133", --server-name, localhost, --trust-file, /etc/positron/tls/ca.pem]
      periodSeconds: 5
      timeoutSeconds: 6
      failureThreshold: 60
    readinessProbe:
      exec:
        command: [/usr/bin/positron, doctor, --ready, --endpoint, "127.0.0.1:13133", --server-name, localhost, --trust-file, /etc/positron/tls/ca.pem]
      periodSeconds: 10
      timeoutSeconds: 6
    livenessProbe:
      exec:
        command: [/usr/bin/positron, doctor, --live, --endpoint, "127.0.0.1:13133", --server-name, localhost, --trust-file, /etc/positron/tls/ca.pem]
      periodSeconds: 10
      timeoutSeconds: 6
    {{- end }}
    volumeMounts:
      - {name: data, mountPath: /var/lib/positron}
      - {name: secrets, mountPath: /var/lib/positron-secrets}
      - {name: backups, mountPath: /var/lib/positron-backups}
      - {name: configuration, mountPath: /etc/positron/positron.toml, subPath: positron.toml, readOnly: true}
      - {name: tls, mountPath: /etc/positron/tls/server.pem, subPath: server.pem, readOnly: true}
      - {name: tls, mountPath: /etc/positron/tls/server-key.pem, subPath: server-key.pem, readOnly: true}
      - {name: tls, mountPath: /etc/positron/tls/ca.pem, subPath: ca.pem, readOnly: true}
      - {name: runtime, mountPath: /run/positron}
      {{- if .Values.operationInputsClaim }}
      - {name: operation-inputs, mountPath: /etc/positron/operations, readOnly: true}
      {{- end }}
volumes:
  - name: data
    persistentVolumeClaim: {claimName: {{ include "positron.name" . }}-data}
  - name: secrets
    persistentVolumeClaim: {claimName: {{ include "positron.name" . }}-secrets}
  - name: backups
    persistentVolumeClaim: {claimName: {{ default (printf "%s-backups" (include "positron.name" .)) .Values.backupClaim }}}
  {{- if .Values.operationInputsClaim }}
  - name: operation-inputs
    persistentVolumeClaim: {claimName: {{ .Values.operationInputsClaim | quote }}}
  {{- end }}
  - name: configuration
    configMap:
      name: {{ include "positron.name" . }}
      defaultMode: 0444
  - name: tls
    secret:
      secretName: {{ .Values.tlsSecret | quote }}
      defaultMode: 0440
  - name: runtime
    emptyDir: {medium: Memory, sizeLimit: 64Mi}
{{- end -}}
