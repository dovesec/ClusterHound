# CH_hasReadVolume

## Edge Schema

- **Source:** [CH_Pod](../NodeDescriptions/CH_Pod.md)
- **Target:** [CH_Volume](../NodeDescriptions/CH_Volume.md)

## General Information

The Pod mounts the target Volume read-only. This is an informational edge: it maps what a given Pod can read from disk so you can triage which pods expose sensitive material without execing into each one. The `containername` edge property identifies which container holds the mount, and the Volume node's `Volume type` and `source` properties show what backs it.

## Abuse

Anyone who controls the Pod can already read its mounts, so this edge does not grant new access; its purpose is to surface where sensitive data sits before you engage. The value depends entirely on what backs the volume, so triage on the Volume node's type first:

- **hostPath** - the node filesystem is mounted into the Pod. Reading it can disclose node-level material (kubelet credentials, `/etc/kubernetes`, container runtime config, `/root/.ssh`), often a direct step toward node or cluster compromise.
- **secret / projected** - credential material, including mounted ServiceAccount tokens, is present on disk.
- **configMap / emptyDir** - usually low value, unless application secrets have been placed there.

```bash
# Triage the mount from within the container
ls -la /path/to/mount
find /path/to/mount -type f 2>/dev/null

# Read sensitive files (value depends on the backing type)
cat /path/to/mount/.env
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

## References

- [Kubernetes Volumes](https://kubernetes.io/docs/concepts/storage/volumes/)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [OWASP K03 - Secrets Management Failures](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K03-Secrets-Management-Failures.html)
