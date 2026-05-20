# unauthAPIAccess

## Edge Schema

- **Source:** [ExternalActor](../NodeDescriptions/ExternalActor.md)
- **Target:** [Node](../NodeDescriptions/Node.md)

## General Information

The Kubernetes API server on the target control plane node accepts unauthenticated requests, enabling an external actor with network access to enumerate or interact with cluster resources.

## Abuse

An unauthenticated API server can be queried directly without credentials. The actual impact depends entirely on what the anonymous user (`system:anonymous`) is permitted to do. In some misconfigurations this is broad, in others it is limited to health endpoints only. Always check `auth can-i --list` as anonymous first to understand the real scope before assuming full access.

```bash
# Enumerate the cluster without credentials
kubectl --server=https://<api-server-ip>:6443 \
  --insecure-skip-tls-verify \
  get pods -A

# Check what anonymous access permits
kubectl --server=https://<api-server-ip>:6443 \
  --insecure-skip-tls-verify \
  auth can-i --list \
  --as=system:anonymous
```

## References

- [Kubernetes API Server Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#anonymous-requests)
- [HackTricks - Pentesting Kubernetes](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/pentesting-kubernetes-services#6443-port-kubernetes-api)
- [OWASP K06 - Overly Exposed Kubernetes Components](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html)
- [OWASP K09 - Broken Authentication Mechanisms](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K09-Broken-Authentication-Mechanisms.html)
- [Threat Matrix - Access Kubernetes API Server](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20the%20K8S%20API%20server/)
- [Threat Matrix - Exposed Sensitive Interfaces](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Exposed%20sensitive%20interfaces/)
