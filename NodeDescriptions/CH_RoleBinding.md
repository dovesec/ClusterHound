# CH_RoleBinding

## Overview

A namespaced RBAC RoleBinding. Source of `CH_bindsRole` edges to the Role or ClusterRole it references.

## Scope

Namespaced

## Properties

| Property | Description |
|----------|-------------|
| name | RoleBinding name |
| namespace | Namespace the RoleBinding belongs to |
| Role ref name | Name of the referenced Role or ClusterRole |
| Role ref kind | Kind of the referenced role: `Role` or `ClusterRole` |
