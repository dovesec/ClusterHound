# ClusterHound - Custom Cypher Queries

These queries are designed for use with [BloodHound CE](https://github.com/SpecterOps/BloodHound) after ingesting ClusterHound data. Import `customqueries.json` via the BloodHound CE UI to load them all at once, or run them directly in the Cypher query box.

| Name | Query |
| ---- | ----- |
| All Nodes of a Specific Type | `MATCH p=(n:Pod:ClusterHound) RETURN p` |
| All Edges of a Specific Type | `MATCH p=(a:ClusterHound)-[:canExec]->(b:ClusterHound) RETURN p` |
| All Edges from a Specific Object | `MATCH p=(n:ClusterHound {objectid: 'NAMESPACE/KIND/NAME'})-[r]->(m:ClusterHound) RETURN p` |
| Specific Edge Type from a Specific Object | `MATCH p=(n:ClusterHound {objectid: 'NAMESPACE/KIND/NAME'})-[:canExec]->(m:ClusterHound) RETURN p` |
| Identities with Full Cluster Access | `MATCH p=(n:ClusterHound)-[:fullAccess]->(c:Cluster:ClusterHound) RETURN p` |
| Nodes Proxy RCE | `MATCH p=(n:Identity:ClusterHound)-[:nodesProxyRCE]->(c:Cluster:ClusterHound) RETURN p` |
| Unauthenticated API and Kubelet Access | `MATCH p=(e:ExternalActor:ClusterHound)-[r:unauthAPIAccess\|unauthKubeletAccess]->(n:ClusterHound) RETURN p` |
| Shortest Path from Identity to Full Cluster Compromise | `MATCH p=shortestPath((n:Identity:ClusterHound)-[*1..10]->(c:Cluster:ClusterHound)) RETURN p` |
| Identities that Can Bind Roles | `MATCH p=(n:Identity:ClusterHound)-[:canBind]->(t:ClusterHound) RETURN p` |
| Identities that Can Escalate Roles | `MATCH p=(n:Identity:ClusterHound)-[:canEscalate]->(t:ClusterHound) RETURN p` |
| Identities Holding Both canBind and canEscalate | `MATCH p=(n:ClusterHound)-[:canBind]->(r:ClusterHound)<-[:canEscalate]-(n) RETURN p` |
| Identities that Can Create Service Account Tokens | `MATCH p=(n:Identity:ClusterHound)-[:canCreateToken]->(t:ClusterHound) RETURN p` |
| Identities that Can Impersonate | `MATCH p=(n:Identity:ClusterHound)-[:canImpersonate]->(t:ClusterHound) RETURN p` |
| Privileged Pods | `MATCH p=(pod:Pod:ClusterHound)-[:podPrivileged]->(n:ClusterHound) RETURN p` |
| Host Namespace Pods | `MATCH p=(pod:Pod:ClusterHound)-[r:podHostPID\|podHostNetwork\|podHostIPC]->(n:ClusterHound) RETURN p` |
| Shortest Paths from Pod to Critical Permissions | `MATCH p=(pod:Pod:ClusterHound)-[:compromiseServiceAccount]->(i:Identity:ClusterHound)-[r:fullAccess\|nodesProxyRCE\|canBind\|canEscalate\|canExec\|canCreate\|canPatch\|canCreateEphemeral\|canImpersonate\|canCreateToken\|secretsRead]->(t:ClusterHound) RETURN p` |
| Pods Reaching IMDS | `MATCH p=(pod:Pod:ClusterHound)-[:accessIMDS]->(imds:IMDSService:ClusterHound) RETURN p` |
| Identities that Can Exec into Pods | `MATCH p=(n:Identity:ClusterHound)-[:canExec]->(t:ClusterHound) RETURN p` |
| Identities that Can Create Pods | `MATCH p=(n:Identity:ClusterHound)-[:canCreate]->(t:ClusterHound) RETURN p` |
| Identities that Can Patch Pods | `MATCH p=(n:Identity:ClusterHound)-[:canPatch]->(t:ClusterHound) RETURN p` |
| Identities that Can Read Secrets | `MATCH p=(n:Identity:ClusterHound)-[:secretsRead]->(t:ClusterHound) RETURN p` |
| Identities that Can Port Forward | `MATCH p=(n:Identity:ClusterHound)-[:canPortForward]->(t:ClusterHound) RETURN p` |
| All Entry Points | `MATCH p=(svc:Service:ClusterHound)-[:entryPoint]->(pod:Pod:ClusterHound) RETURN p` |
| Full Attack Chain - Entry Point to Critical Permissions | `MATCH p=(svc:Service:ClusterHound)-[:entryPoint]->(pod:Pod:ClusterHound)-[:compromiseServiceAccount]->(i:Identity:ClusterHound)-[r:fullAccess\|nodesProxyRCE\|canBind\|canEscalate\|canExec\|canCreate\|canPatch\|canCreateEphemeral\|canImpersonate\|canCreateToken\|secretsRead]->(t:ClusterHound) RETURN p` |
| Pods with Write Volume Mounts | `MATCH p=(pod:Pod:ClusterHound)-[:hasWriteVolume]->(v:Volume:ClusterHound) RETURN p` |
| Pods with Read Volume Mounts | `MATCH p=(pod:Pod:ClusterHound)-[:hasReadVolume]->(v:Volume:ClusterHound) RETURN p` |
