# canCreateToken

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Identity](../NodeDescriptions/Identity.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `create` on the `serviceaccounts/token` subresource, allowing it to request a valid token for the target ServiceAccount via the TokenRequest API and assume its permissions. Points to specific ServiceAccount(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.
