# podHostPID

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Node](../NodeDescriptions/Node.md)

## General Information

The Pod runs with `hostPID: true`, sharing the Node's PID namespace and enabling inspection or signalling of all host processes from within the container.
