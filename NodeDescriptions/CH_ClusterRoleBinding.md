# CH_ClusterRoleBinding

## Overview

A cluster-scoped RBAC ClusterRoleBinding. Source of `CH_bindsRole` edges to the ClusterRole it references.

## Scope

Cluster

## Properties

| Property | Description |
|----------|-------------|
| name | ClusterRoleBinding name |
| Role ref name | Name of the referenced ClusterRole |
| Role ref kind | Always `ClusterRole` |
