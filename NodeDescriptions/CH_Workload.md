# CH_Workload

## Overview

A Workload node represents any Kubernetes resource that manages a pod template and is responsible for creating and maintaining pods. The `kind` property identifies the specific controller type.

| Kind | API Group | Description |
|------|-----------|-------------|
| Deployment | apps/v1 | Manages ReplicaSets to provide declarative pod updates |
| StatefulSet | apps/v1 | Manages pods with stable identities and persistent storage |
| DaemonSet | apps/v1 | Ensures a copy of a pod runs on every (or selected) node |
| ReplicaSet | apps/v1 | Maintains a stable set of replica pods |
| ReplicationController | v1 | Legacy predecessor to ReplicaSet |
| Job | batch/v1 | Runs pods to completion for batch workloads |
| CronJob | batch/v1 | Creates Jobs on a scheduled basis |

## Scope

One node per workload resource instance. Namespaced.

## Properties

| Property | Description |
|----------|-------------|
| name | Resource name |
| namespace | Namespace the resource belongs to |
| kind | Controller type (Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob) |
