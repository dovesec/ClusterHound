# CH_Secret

## Overview

A Kubernetes Secret. Target of `CH_secretsRead` edges when an Identity has permission to read specific named secrets.

## Scope

Namespaced

## Properties

| Property | Description |
|----------|-------------|
| name | Secret name |
| namespace | Namespace the Secret belongs to |
| type | Secret type (e.g. `Opaque`, `kubernetes.io/service-account-token`, `kubernetes.io/tls`) |
