# hasReadVolume

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Volume](../NodeDescriptions/Volume.md)

## General Information

The Pod has a read-capable mount of the target Volume, potentially exposing sensitive data accessible within the container's filesystem. Edge property `containername` identifies which container holds the mount.

## Abuse

Access the mount path within the container and enumerate its contents. The value varies significantly by volume type: a hostPath mount of `/` or `/etc` is critical, a ConfigMap with non-sensitive configuration is not. The `containername` edge property identifies which container holds the mount. Check the Volume node's properties for type and source path to triage quickly before investigating further.

```bash
# Enumerate the mount from within the container
ls -la /path/to/mount
find /path/to/mount -type f 2>/dev/null

# Read sensitive files
cat /path/to/mount/.env
cat /path/to/mount/credentials
cat /path/to/mount/config.yaml
```

## References

- [Kubernetes Volumes](https://kubernetes.io/docs/concepts/storage/volumes/)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [OWASP K03 - Secrets Management Failures](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K03-Secrets-Management-Failures.html)
