# podHostIPC

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Node](../NodeDescriptions/Node.md)

## General Information

The Pod runs with `hostIPC: true`, sharing the Node's IPC namespace and potentially enabling access to shared memory segments of other host processes.

## Abuse

With access to the host IPC namespace, enumerate shared memory segments and message queues used by host processes, and inspect `/dev/shm` for files written by other pods or host services. Impact depends on whether anything useful is actively stored in shared memory; databases and legacy applications occasionally expose credentials or session data this way. This is the weakest of the three host namespace edges on its own but can complement other findings.

```bash
# Check shared memory files written by host processes or other pods
ls -al /dev/shm/

# Enumerate all IPC resources on the host
ipcs -a

# Inspect a specific shared memory segment
ipcs -m -i <shmid>
```

## References

- [BishopFox badPods - hostIPC](https://github.com/BishopFox/badPods/tree/main/manifests/hostipc)
- [Kubernetes hostIPC](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [HackTricks - hostIPC](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/escaping-from-kubernetes/kubernetes-node-local-privilege-escalation#hostipc)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
