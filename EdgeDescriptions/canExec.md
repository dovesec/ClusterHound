# canExec

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Pod](../NodeDescriptions/Pod.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `pods/exec` permission, allowing arbitrary command execution within Pod containers. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.
