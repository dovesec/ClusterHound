# CH_canPortForward

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Pod](../NodeDescriptions/CH_Pod.md) / [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `pods/portforward` permission, enabling tunnelling into the Pod's network stack for lateral movement. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.

## Abuse

Forward a local port to a port on the target pod, providing direct access to services running inside the pod that are not externally exposed. This does not provide code execution on its own; its value is lateral movement to internal services such as databases, admin interfaces, and internal APIs that are otherwise unreachable from outside.

```bash
# Forward local port to pod port
kubectl port-forward pod/<pod> -n <namespace> <local-port>:<pod-port>

# Access the forwarded service
curl http://localhost:<local-port>

# Forward to a database port for direct access
kubectl port-forward pod/<pod> -n <namespace> 5432:5432
```

## References

- [kubectl port-forward](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_port-forward/)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [Threat Matrix - Cluster Internal Networking](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster%20internal%20networking/)
