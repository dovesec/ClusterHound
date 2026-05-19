# canAttach

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Pod](../NodeDescriptions/Pod.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `pods/attach` permission, allowing attachment to a running container process and interaction with its stdin/stdout. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.
