# CH_secretsCreate

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Namespace](../NodeDescriptions/CH_Namespace.md) / [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds `create` permission on secrets. Because creation implies the resource does not yet exist, the edge points to the Namespace or Cluster the permission applies to.

The security-relevant consequence is ServiceAccount assumption. If an identity can create a Secret, it can plant a Secret of type `kubernetes.io/service-account-token` annotated with `kubernetes.io/service-account.name: <target>`. The token controller (part of kube-controller-manager) then populates the Secret's `data.token` field with a valid, long-lived token for that ServiceAccount. Reading the Secret back yields a credential that authenticates as the target ServiceAccount - so `create` together with `get` on secrets in a namespace is equivalent to assuming any ServiceAccount in it.

Kubernetes 1.24 stopped auto-generating these token Secrets for every ServiceAccount, but the controller still honours manually created ones. This was validated end-to-end on Kubernetes v1.32.2: the planted Secret was populated and the resulting token authenticated as the named ServiceAccount with its full permissions.

The token produced this way is long-lived and non-expiring, unlike the time-bound tokens from the TokenRequest API ([CH_canCreateToken](CH_canCreateToken.md)), making this both an assumption and a persistence technique.

## Abuse

Write a manifest for a `kubernetes.io/service-account-token` Secret annotated for the target ServiceAccount, apply it, wait for the token controller to populate it, then read the token back and use it to authenticate as that ServiceAccount. This requires `get` (or `list`) on secrets in addition to `create`, to read the populated token.

```bash
# 1. Plant a token Secret for the target ServiceAccount
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: minted
  namespace: <namespace>
  annotations:
    kubernetes.io/service-account.name: <target-sa>
type: kubernetes.io/service-account-token
EOF

# 2. The controller populates data.token within a second or two - read it back
kubectl get secret minted -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d

# 3. Authenticate as the target ServiceAccount with the minted token
kubectl --token=<token> auth whoami
```

Note: when testing locally, a kubeconfig client certificate takes precedence over `--token`. Use an empty kubeconfig (e.g. `KUBECONFIG=$(mktemp)`) with `--server` and `--token` to confirm the token's own identity.

## References

- [Kubernetes ServiceAccount Tokens](https://kubernetes.io/docs/concepts/security/service-accounts/#manually-create-a-long-lived-api-token-for-a-serviceaccount)
- [Kubernetes Secrets - ServiceAccount token Secrets](https://kubernetes.io/docs/concepts/configuration/secret/#service-account-token-secrets)
- [HackTricks - Abusing Roles/ClusterRoles in Kubernetes](https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)