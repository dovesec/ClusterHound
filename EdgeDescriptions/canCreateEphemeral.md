# canCreateEphemeral

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Pod](../NodeDescriptions/Pod.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `pods/ephemeralcontainers` permission, allowing injection of ephemeral debug containers into running Pods. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.
