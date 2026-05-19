# fullAccess

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds wildcard RBAC permissions (`*` verbs on `*` resources), granting unrestricted access to all resources across the entire cluster. All other RBAC edges are suppressed for this Identity.
