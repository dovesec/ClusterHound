<p align="center">
  <img src="logo.svg" alt="ClusterHound" width="520"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/BloodHound-CE-red?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Kubernetes-326CE5?style=flat-square&logo=kubernetes&logoColor=white"/>
</p>

---

## Coming soon to a BSides near you...

## Nodes

| Node | Scope | Description |
| -------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Cluster` | Cluster | Represents the target Kubernetes cluster. Acts as the convergence point for cluster-wide attack paths including `fullAccess`, `nodesProxyRCE`, `canBind` and `canEscalate` on ClusterRoles, and `canImpersonate` with cluster-wide scope |
| `ExternalActor` | Cluster | Synthetic node representing an unauthenticated external threat actor with network-level visibility of the API server or Kubelet API. Source of `unauthAPIAccess` and `unauthKubeletAccess` edges |
| `Node` | Cluster | A Kubernetes worker or control plane node. Enriched with OS, kernel, kubelet version and internal IP where the nodes API is accessible. Synthesised as a placeholder from `spec.nodeName` on Pod specs when the nodes API is inaccessible |
| `Namespace` | Cluster | A Kubernetes namespace, derived from collected resources. Acts as the target for namespace-scoped RBAC edges (`canExec`, `canPatch`, `canBind`, etc.) when no `resourceNames` restriction is present |
| `Pod` | Namespaced | A running Pod. Source of privilege escalation edges to Nodes (`podPrivileged`, `hostPID`, etc.), `compromiseServiceAccount` to its ServiceAccount, and volume mount edges to Volumes |
| `Service` | Namespaced | A Kubernetes Service. Source of `entryPoint` edges to Pods whose labels match the Service selector, representing potential initial access paths into the cluster |
| `Secret` | Namespaced | A Kubernetes Secret. Target of `secretsRead` edges when an Identity has permission to read specific named secrets |
| `Identity` | Namespaced / Cluster | Represents a ServiceAccount, User, or Group. ServiceAccounts are collected from the API; Users and Groups are discovered dynamically from binding subjects. Source of all RBAC-derived attack edges |
| `Volume` | Namespaced | A volume declared in a Pod spec. Target of `hasReadVolume` and `hasWriteVolume` edges. Resolved through PVC → PV chains where applicable and enriched with volume type and source path |
| `Role` | Namespaced | A namespaced RBAC Role. Target of `bindsRole` edges from RoleBindings. Retained in the graph to preserve the structural binding chain |
| `ClusterRole` | Cluster | A cluster-scoped RBAC ClusterRole. Target of `bindsRole` edges from RoleBindings and ClusterRoleBindings. Retained in the graph to preserve the structural binding chain |
| `RoleBinding` | Namespaced | A namespaced RBAC RoleBinding. Source of `bindsRole` edges to the Role or ClusterRole it references |
| `ClusterRoleBinding` | Cluster | A cluster-scoped RBAC ClusterRoleBinding. Source of `bindsRole` edges to the ClusterRole it references |
| `IMDSService` | Cluster | Represents the cloud provider instance metadata endpoint. Detected from node `spec.providerID` and labels. Supports AWS, Azure, and GCP. Target of `accessIMDS` edges from Pods |

---

## Edges

| Edge | Source → Target | Description |
| -------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nodesProxyRCE` | Identity → Cluster | The Identity holds the `nodes/proxy` GET permission, which can be abused to proxy requests directly to the Kubelet API on any node, facilitating RCE to all Pods on that node |
| `secretsRead` | Identity → Secret / Namespace / Cluster | The Identity holds `get` or `list` permissions on secrets. Points to specific Secret(s) if `resourceNames` is set, otherwise to the Namespace or Cluster the permission applies to |
| `unauthAPIAccess` | ExternalActor → Node | The Kubernetes API server on the target control plane node accepts unauthenticated requests, enabling an external actor with network access to enumerate or interact with cluster resources |
| `unauthKubeletAccess` | ExternalActor → Node | The Kubelet API on the target worker node is accessible without authentication, enabling an external actor with network access to list Pods, exec into containers, or read logs |
| `hasReadVolume` | Pod → Volume | The Pod has a read-capable mount of the target Volume, potentially exposing sensitive data accessible within the container's filesystem. Edge property `containername` identifies which container holds the mount |
| `hasWriteVolume` | Pod → Volume | The Pod has a write-capable mount of the target Volume, potentially allowing modification of data, configuration, or binaries accessible to other workloads. Edge property `containername` identifies which container holds the mount |
| `compromiseServiceAccount` | Pod → Identity | The Pod mounts a ServiceAccount token, meaning compromise of any container in the Pod yields the ServiceAccount's credentials and all associated permissions |
| `canPatch` | Identity → Pod / Namespace / Cluster | The Identity holds `patch` or `update` permissions on Pods, allowing modification of the Pod spec including injection of new containers or environment variables. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster |
| `canExec` | Identity → Pod / Namespace / Cluster | The Identity holds `pods/exec` permission, allowing arbitrary command execution within Pod containers. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster |
| `canCreate` | Identity → Pod / Namespace / Cluster | The Identity holds `create` permission on Pods, allowing deployment of new workloads with arbitrary specs including privileged containers or sensitive volume mounts. Points to the Namespace or Cluster the permission applies to |
| `canCreateEphemeral` | Identity → Pod / Namespace / Cluster | The Identity holds `pods/ephemeralcontainers` permission, allowing injection of ephemeral debug containers into running Pods. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster |
| `canAttach` | Identity → Pod / Namespace / Cluster | The Identity holds `pods/attach` permission, allowing attachment to a running container process and interaction with its stdin/stdout. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster |
| `canPortForward` | Identity → Pod / Namespace / Cluster | The Identity holds `pods/portforward` permission, enabling tunnelling into the Pod's network stack for lateral movement. Points to specific Pod(s) if `resourceNames` is set, otherwise to the Namespace or Cluster |
| `canCreateToken` | Identity → Identity / Namespace / Cluster | The Identity holds `create` on the `serviceaccounts/token` subresource, allowing it to request a valid token for the target ServiceAccount via the TokenRequest API and assume its permissions. Points to specific ServiceAccount(s) if `resourceNames` is set, otherwise to the Namespace or Cluster |
| `fullAccess` | Identity → Cluster | The Identity holds wildcard RBAC permissions (`*` verbs on `*` resources), granting unrestricted access to all resources across the entire cluster. All other RBAC edges are suppressed for this Identity |
| `canImpersonate` | Identity → Namespace / Cluster | The Identity holds `impersonate` permissions, allowing it to make API requests as other identities. Edge property `resource` indicates whether serviceaccounts, users, or groups can be impersonated. Points to Namespace if scoped, Cluster if cluster-wide |
| `podPrivileged` | Pod → Node | The Pod runs with `privileged: true` in its security context, meaning container compromise provides a direct path to full control of the underlying Node |
| `podHostPID` | Pod → Node | The Pod runs with `hostPID: true`, sharing the Node's PID namespace and enabling inspection or signalling of all host processes from within the container |
| `podHostNetwork` | Pod → Node | The Pod runs with `hostNetwork: true`, sharing the Node's network namespace and enabling access to all network interfaces and locally bound services on the host |
| `podHostIPC` | Pod → Node | The Pod runs with `hostIPC: true`, sharing the Node's IPC namespace and potentially enabling access to shared memory segments of other host processes |
| `entryPoint` | Service → Pod | The Service exposes the target Pod to external or internal traffic, representing a potential initial access point into the cluster for a threat actor |
| `canBind` | Identity → Namespace / Cluster | The Identity holds `create` or `patch` permissions on RoleBindings or ClusterRoleBindings. Points to the Namespace for RoleBinding permissions, Cluster for ClusterRoleBinding permissions |
| `canEscalate` | Identity → Namespace / Cluster | The Identity holds the `escalate` verb on Roles or ClusterRoles, allowing creation or update of roles with permissions exceeding its own. Points to the Namespace for Role permissions, Cluster for ClusterRole permissions |
| `bindsRole` | RoleBinding → Role / ClusterRole \| ClusterRoleBinding → ClusterRole | The Binding grants the permissions defined in the target Role or ClusterRole to its listed subjects, forming the structural link between a binding and the role it references |
| `accessIMDS` | Pod → IMDSService | The Pod can potentially reach the cloud provider metadata endpoint. Does not currently check NetworkPolicies or IMDSv2 hop-limit enforcement — treat as a potential path pending manual verification |
