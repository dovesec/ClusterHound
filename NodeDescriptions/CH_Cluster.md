# CH_Cluster

## Overview

Represents the target Kubernetes cluster. Acts as the convergence point for cluster-wide attack paths including `CH_fullAccess`, `CH_nodesProxyRCE`, `CH_canBind` and `CH_canEscalate` on ClusterRoles, and `CH_canImpersonate` with cluster-wide scope.

## Scope

Cluster

## Properties

| Property | Description |
|----------|-------------|
| name | Cluster display name, derived from the kubectl context and auto-sanitised for EKS ARN, GKE, and OpenShift formats |
