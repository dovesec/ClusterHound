# hasWriteVolume

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Volume](../NodeDescriptions/Volume.md)

## General Information

The Pod has a write-capable mount of the target Volume, potentially allowing modification of data, configuration, or binaries accessible to other workloads. Edge property `containername` identifies which container holds the mount.
