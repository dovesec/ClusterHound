# canCreate

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Pod](../NodeDescriptions/Pod.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `create` permission on Pods, allowing deployment of new workloads with arbitrary specs including privileged containers or sensitive volume mounts. Points to the Namespace or Cluster the permission applies to.
