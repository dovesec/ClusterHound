# CH_canCreate

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## Edge Properties

| Property | Description |
|----------|-------------|
| resource | Comma-separated list of resource types the identity can create (e.g. `Pod`, `Deployment`, `Pod,StatefulSet`). Multiple permitted types on the same target are merged into a single edge. |

## General Information

The Identity holds `create` permission on Pods and/or pod-creating workload controllers (Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob). Since creation implies the resource does not yet exist, the edge always points to the Namespace or Cluster the permission applies to. The `resource` edge property identifies what can be created.

## Abuse

Check the `resource` edge property to understand what can be created. The end goal is the same in all cases — running a pod with a malicious spec — but the path differs slightly.

For direct pod creation (`resource` contains `Pod`), the spec is supplied at creation time. For workload controllers (Deployment, StatefulSet, etc.), the malicious spec goes in the pod template and the controller creates the pods. The workload approach has an added persistence advantage: if the pod is deleted the controller simply recreates it.

In all cases the actual impact is gated by whatever admission controls are in place. Pod Security Admission (PSA), OPA/Gatekeeper, Kyverno, or SCCs may block dangerous configurations even if the RBAC permission exists. Start with a benign spec to confirm the permission works, then escalate. The BishopFox badPods project referenced below covers the full range of attack specs for all types of resources, from fully privileged node escapes down to what is achievable with a single dangerous capability.

```bash
# Confirm the permission works with a benign pod first
kubectl run test --image=busybox --restart=Never -n <namespace> -- sleep 3600

# Create a malicious Deployment (or similar) if resource includes a workload type
kubectl create deployment pwned --image=<malicious-image> -n <namespace>
```

## References

- [Kubernetes Pod Security](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [BishopFox badPods](https://github.com/BishopFox/badPods)
- [HackTricks - Create Privileged Pod](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes#create-pods)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [OWASP K04 - Lack Of Cluster Level Policy Enforcement](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K04-Lack-Of-Cluster-Level-Policy-Enforcement.html)
- [Threat Matrix - Privileged Container](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Privileged%20container/)
