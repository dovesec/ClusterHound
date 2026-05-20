# canAttach

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Pod](../NodeDescriptions/Pod.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `pods/attach` permission, allowing attachment to a running container process and interaction with its stdin/stdout. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.

## Abuse

Attach to a running container's process to interact with its stdin/stdout. Unlike `canExec` which spawns a new process, attach connects to the existing PID 1. For most production containers (nginx, Java apps, Python services etc.) this is largely useless: you see stdout and send noise to stdin that the process ignores. It becomes meaningful when the container is running an interactive shell as PID 1, a REPL (Python, Node, Ruby) where sending input executes code, or a process that explicitly reads commands from stdin.

```bash
# Attach to the main process of a container
kubectl attach -it <pod> -n <namespace> -c <container>
```

## References

- [kubectl attach](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_attach/)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
