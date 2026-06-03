# CH_canExec

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Pod](../NodeDescriptions/CH_Pod.md) / [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `pods/exec` permission, allowing arbitrary command execution within Pod containers. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.

## Abuse

Exec directly into a running container to gain an interactive shell or run commands.

```bash
# Interactive shell
kubectl exec -it <pod> -n <namespace> -- /bin/sh

# Run a single command
kubectl exec <pod> -n <namespace> -- cat /etc/passwd

# Target a specific container in a multi-container pod
kubectl exec -it <pod> -n <namespace> -c <container> -- /bin/bash
```

## References

- [kubectl exec](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_exec/)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [Threat Matrix - Exec into Container](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exec%20into%20container/)
