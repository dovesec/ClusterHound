# hasReadVolume

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Volume](../NodeDescriptions/Volume.md)

## General Information

The Pod has a read-capable mount of the target Volume, potentially exposing sensitive data accessible within the container's filesystem. Edge property `containername` identifies which container holds the mount.
