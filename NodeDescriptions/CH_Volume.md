# CH_Volume

## Overview

A volume declared in a Pod spec. Target of `CH_hasReadVolume` and `CH_hasWriteVolume` edges. Resolved through PVC → PV chains where applicable and enriched with volume type and source path.

## Scope

Namespaced

## Properties

| Property | Description |
|----------|-------------|
| name | Volume name as declared in the Pod spec |
| namespace | Namespace of the owning Pod |
| Pod name | Name of the Pod this volume belongs to |
| Volume type | Volume type: `hostPath`, `secret`, `configMap`, `persistentVolumeClaim`, `projected`, `emptyDir`, `nfs`, `csi`, or `unknown` |
| source | Source detail - path for hostPath, secret name, PVC claim chain with PV resolution and underlying storage details, driver name for CSI, etc. |
