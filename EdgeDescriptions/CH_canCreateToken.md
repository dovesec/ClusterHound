# CH_canCreateToken

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Identity](../NodeDescriptions/CH_Identity.md) / [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `create` on the `serviceaccounts/token` subresource, allowing it to request a valid token for the target ServiceAccount via the TokenRequest API and assume its permissions. Points to specific ServiceAccount(s) if `resourceNames` is set, otherwise to the Namespace or Cluster.

## Abuse

Request a token for any ServiceAccount in scope and use it to authenticate to the API server as that identity. The token duration is configurable at request time with `--duration` (default 1 hour); the upper limit is set by the API server's `--service-account-max-token-expiration` flag, which defaults to 1 hour but can be raised. This is a cleaner path than reading a secret-mounted token via `CH_mountsServiceAccount`; it leaves less trace and works even when the target ServiceAccount has `automountServiceAccountToken` disabled, since the token is requested directly from the API server rather than read from a pod mount.

```bash
# Request a token for a target ServiceAccount
kubectl create token <serviceaccount> -n <namespace>

# Request a longer-lived token (default is 1 hour)
kubectl create token <serviceaccount> -n <namespace> \
  --duration=24h

# Use the token
kubectl --token=<token> auth can-i --list
```

## References

- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)
- [HackTricks - Abusing Roles/ClusterRoles in Kubernetes](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [Threat Matrix - Container Service Account](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/container%20service%20account/)
