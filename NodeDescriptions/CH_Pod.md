# CH_Pod

## Overview

A running Pod. Source of privilege escalation edges to Nodes (`CH_podPrivileged`, `CH_podHostPID`, `CH_podHostNetwork`, `CH_podHostIPC`), `CH_mountsServiceAccount` to its ServiceAccount, and volume mount edges to Volumes.

## Scope

Namespaced

## Properties

| Property | Description |
|----------|-------------|
| name | Pod name |
| namespace | Namespace the Pod runs in |
| Node name | Name of the Kubernetes node the Pod is scheduled on |
| Service account name | Name of the mounted service account (defaults to `default`) |
| phase | Pod phase: Running, Pending, Succeeded, Failed, or Unknown |
| Host PID | `true` if the Pod shares the host PID namespace |
| Host network | `true` if the Pod shares the host network namespace |
| Host IPC | `true` if the Pod shares the host IPC namespace |
