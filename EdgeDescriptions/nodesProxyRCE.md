# nodesProxyRCE

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds the `nodes/proxy` GET permission, which can be abused to proxy requests directly to the Kubelet API on any node, facilitating RCE to all Pods on that node.
