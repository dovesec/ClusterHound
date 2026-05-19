# canPatch

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Pod](../NodeDescriptions/Pod.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `patch` or `update` permissions on Pods, allowing modification of the Pod spec including injection of new containers or environment variables. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.
