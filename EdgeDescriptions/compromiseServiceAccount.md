# compromiseServiceAccount

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Identity](../NodeDescriptions/Identity.md)

## General Information

The Pod mounts a ServiceAccount token, meaning compromise of any container in the Pod yields the ServiceAccount's credentials and all associated permissions.
