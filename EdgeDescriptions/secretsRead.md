# secretsRead

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Secret](../NodeDescriptions/Secret.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `get` or `list` permissions on secrets. Points to specific Secret(s) if `resourceNames` is set, otherwise to the Namespace or Cluster the permission applies to.
