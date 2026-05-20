# secretsRead

## Edge Schema

- **Source:** [Identity](../NodeDescriptions/Identity.md)
- **Target:** [Secret](../NodeDescriptions/Secret.md) / [Namespace](../NodeDescriptions/Namespace.md) / [Cluster](../NodeDescriptions/Cluster.md)

## General Information

The Identity holds `get` or `list` permissions on secrets. Points to specific Secret(s) if `resourceNames` is set, otherwise to the Namespace or Cluster the permission applies to.

## Abuse

Read secrets directly using kubectl. Values are base64-encoded and must be decoded. Common high-value targets include service account tokens, TLS certificates, database credentials, and API keys. Both `get` and `list` expose full secret values — Kubernetes returns complete Secret objects including their `data` fields on a `list` call, so there is no meaningful security distinction between the two verbs for secrets.

```bash
# Read a specific secret
kubectl get secret <name> -n <namespace> -o json

# Decode a specific key
kubectl get secret <name> -n <namespace> \
  -o jsonpath='{.data.<key>}' | base64 -d

# List all secrets in scope
kubectl get secrets -A
```

## References

- [Kubernetes Secrets](https://kubernetes.io/docs/concepts/configuration/secret/)
- [HackTricks - Kubernetes Secrets](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-access-to-other-clouds-resources/kubernetes-secrets)
- [OWASP K03 - Secrets Management Failures](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K03-Secrets-Management-Failures.html)
- [Threat Matrix - List K8S Secrets](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/List%20K8S%20secrets/)
