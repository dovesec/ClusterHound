# canImpersonate

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `impersonate` permissions, allowing it to make API requests as other identities. Edge property `resource` indicates whether serviceaccounts, users, or groups can be impersonated. Points to Namespace if scoped, Cluster if cluster-wide.
