# podPrivileged

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Node](../NodeDescriptions/Node.md)

## General Information

The Pod runs with `privileged: true` in its security context, meaning container compromise provides a direct path to full control of the underlying Node.
