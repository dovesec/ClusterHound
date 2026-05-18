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
|---|---|---|
| `Cluster` | Cluster | The target Kubernetes cluster |
| `ExternalActor` | Cluster | Synthetic unauthenticated external threat actor |
| `Node` | Cluster | Worker or control plane node |
| `Namespace` | Cluster | Kubernetes namespace |
| `Pod` | Namespaced | Running pod |
| `Service` | Namespaced | Kubernetes Service |
| `Secret` | Namespaced | Kubernetes Secret |
| `Identity` | Namespaced / Cluster | ServiceAccount, User, or Group |
| `Volume` | Namespaced | Pod volume |
| `Role` | Namespaced | Namespaced RBAC Role |
| `ClusterRole` | Cluster | Cluster-scoped RBAC ClusterRole |
| `RoleBinding` | Namespaced | Namespaced RoleBinding |
| `ClusterRoleBinding` | Cluster | Cluster-scoped ClusterRoleBinding |
| `IMDSService` | Cluster | Cloud provider instance metadata endpoint (AWS / Azure / GCP) |

---

## Edges

| Edge | Source → Target | Description |
|---|---|---|
| `fullAccess` | Identity → Cluster | Wildcard RBAC — unrestricted access to all resources |
| `nodesProxyRCE` | Identity → Cluster | `nodes/proxy` GET permission enables Kubelet API proxying → RCE |
| `unauthAPIAccess` | ExternalActor → Node | API server accepts unauthenticated requests |
| `unauthKubeletAccess` | ExternalActor → Node | Kubelet API accessible without authentication |
| `podPrivileged` | Pod → Node | Pod runs with `privileged: true` |
| `podHostPID` | Pod → Node | Pod runs with `hostPID: true` |
| `podHostNetwork` | Pod → Node | Pod runs with `hostNetwork: true` |
| `podHostIPC` | Pod → Node | Pod runs with `hostIPC: true` |
| `canExec` | Identity → Pod / Namespace / Cluster | `pods/exec` permission |
| `canCreate` | Identity → Pod / Namespace / Cluster | `create` on Pods |
| `canPatch` | Identity → Pod / Namespace / Cluster | `patch` or `update` on Pods |
| `canCreateEphemeral` | Identity → Pod / Namespace / Cluster | `pods/ephemeralcontainers` permission |
| `canAttach` | Identity → Pod / Namespace / Cluster | `pods/attach` permission |
| `compromiseServiceAccount` | Pod → Identity | Pod mounts a ServiceAccount token |
| `canBind` | Identity → Namespace / Cluster | `create` or `patch` on RoleBindings / ClusterRoleBindings |
| `canEscalate` | Identity → Namespace / Cluster | `escalate` verb on Roles / ClusterRoles |
| `canImpersonate` | Identity → Namespace / Cluster | `impersonate` permission |
| `canCreateToken` | Identity → Identity / Namespace / Cluster | `create` on `serviceaccounts/token` |
| `secretsRead` | Identity → Secret / Namespace / Cluster | `get` or `list` on secrets |
| `hasWriteVolume` | Pod → Volume | Pod has a write-capable volume mount |
| `hasReadVolume` | Pod → Volume | Pod has a read-capable volume mount |
| `canPortForward` | Identity → Pod / Namespace / Cluster | `pods/portforward` permission |
| `accessIMDS` | Pod → IMDSService | Pod can potentially reach the cloud metadata endpoint |
| `entryPoint` | Service → Pod | Service selector matches the Pod |
| `bindsRole` | RoleBinding → Role / ClusterRole | Structural link between a binding and its role |
