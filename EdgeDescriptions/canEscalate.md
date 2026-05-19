# canEscalate

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds the `escalate` verb on Roles or ClusterRoles, allowing creation or update of roles with permissions exceeding its own. Points to the Namespace for Role permissions, Cluster for ClusterRole permissions.
