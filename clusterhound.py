#!/usr/bin/env python3
"""
ClusterHound - Kubernetes attack path collector for BloodHound
Collects cluster data and transforms it into OpenGraph JSON format
for ingestion into BloodHound CE.
"""

import argparse
import json
import logging
import subprocess
import sys
from datetime import datetime, timezone


# ============================================================
# kubectl helpers
# ============================================================

def kubectl_json(*args):
    """Run a kubectl command with -o json and return parsed output."""
    cmd = ["kubectl"] + list(args) + ["-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        logging.warning(f"kubectl failed: {' '.join(cmd)}\n{e.stderr.strip()}")
        return None
    except json.JSONDecodeError as e:
        logging.warning(f"Failed to parse kubectl output as JSON: {e}")
        return None


def kubectl_raw(*args):
    """Run a kubectl command and return raw stdout text."""
    cmd = ["kubectl"] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.warning(f"kubectl failed: {' '.join(cmd)}\n{e.stderr.strip()}")
        return None


def get_items(resource, cluster_scoped=False, namespace=None):
    """Collect all items of a resource type, cluster-wide or namespaced."""
    if cluster_scoped:
        result = kubectl_json("get", resource)
    elif namespace:
        result = kubectl_json("get", resource, "-n", namespace)
    else:
        result = kubectl_json("get", resource, "--all-namespaces")
    if result and "items" in result:
        return result["items"]
    return []


# ============================================================
# Node ID helpers and property utilities
# ============================================================

def clean_props(props):
    """
    Remove None values from a property dict before output.
    The OpenGraph schema only allows primitive values — null is rejected
    by BloodHound's schema validator.
    """
    return {k: v for k, v in props.items() if v is not None}


def nid(namespace, kind, name):
    """
    Build a consistent node ID following kubectl naming conventions.
    Namespaced:     default/pod/nginx-abc123
    Cluster-scoped: cluster/node/worker-1
    """
    kind = kind.lower()
    if namespace:
        return f"{namespace}/{kind}/{name}"
    return f"cluster/{kind}/{name}"


# ============================================================
# Data collection
# ============================================================

def collect_all(namespace=None):
    """Collect all required Kubernetes resources via kubectl."""
    logging.info("Starting cluster data collection...")
    if namespace:
        logging.info(f"  Scope: namespace '{namespace}'")
    else:
        logging.info("  Scope: cluster-wide")

    namespaced = [
        "pods", "services", "secrets", "serviceaccounts",
        "roles", "rolebindings", "persistentvolumeclaims",
    ]
    cluster_scoped = [
        "nodes", "clusterroles", "clusterrolebindings", "persistentvolumes",
    ]

    data = {}
    for resource in namespaced:
        logging.info(f"  Collecting {resource}...")
        data[resource] = get_items(resource, cluster_scoped=False, namespace=namespace)
        logging.debug(f"    -> {len(data[resource])} items")

    for resource in cluster_scoped:
        logging.info(f"  Collecting {resource}...")
        data[resource] = get_items(resource, cluster_scoped=True)
        logging.debug(f"    -> {len(data[resource])} items")

    return data


# ============================================================
# RBAC resolver
# ============================================================

class RBACResolver:
    """
    Resolves Kubernetes RBAC into a flat map of identity → permissions.
    Abstracts Roles, ClusterRoles and their Bindings away so that edges
    can be drawn directly from an Identity to a capability target.
    """

    def __init__(self, roles, clusterroles, rolebindings, clusterrolebindings):
        # Index roles by namespace/name for fast lookup
        self.roles = {
            f"{r['metadata']['namespace']}/{r['metadata']['name']}": r
            for r in roles
        }
        self.clusterroles = {
            cr["metadata"]["name"]: cr for cr in clusterroles
        }
        self.rolebindings = rolebindings
        self.clusterrolebindings = clusterrolebindings

    def _subject_to_id(self, subject, fallback_namespace):
        """Convert a binding subject dict to a node ID string."""
        kind = subject.get("kind", "")
        name = subject.get("name", "")
        namespace = subject.get("namespace") or fallback_namespace

        if kind == "ServiceAccount":
            return nid(namespace, "serviceaccount", name)
        elif kind == "User":
            return nid(None, "user", name)
        elif kind == "Group":
            return nid(None, "group", name)
        return None

    @staticmethod
    def _extract_permissions(rules):
        """
        Flatten a list of RBAC policy rules into individual permission dicts.
        Handles subresources expressed as "resource/subresource" in the
        resources field (e.g. "pods/exec").
        """
        permissions = []
        for rule in (rules or []):
            verbs = rule.get("verbs", [])
            resources = rule.get("resources", [])
            resource_names = rule.get("resourceNames", [])

            for resource_entry in resources:
                if "/" in resource_entry:
                    resource, subresource = resource_entry.split("/", 1)
                else:
                    resource, subresource = resource_entry, None

                for verb in verbs:
                    permissions.append({
                        "resource": resource,
                        "subresource": subresource,
                        "verb": verb,
                        "resource_names": resource_names,
                    })
        return permissions

    def resolve(self):
        """
        Returns a dict mapping identity_id -> list of permission dicts.
        Each permission dict has: resource, subresource, verb, resource_names, namespace.
        namespace=None means the permission applies cluster-wide.
        """
        identity_perms = {}

        def record(identity_id, perms, namespace):
            if not identity_id:
                return
            if identity_id not in identity_perms:
                identity_perms[identity_id] = []
            for p in perms:
                identity_perms[identity_id].append({**p, "namespace": namespace})

        # ClusterRoleBindings → cluster-wide permissions
        for crb in self.clusterrolebindings:
            role_ref = crb.get("roleRef", {})
            subjects = crb.get("subjects") or []

            if role_ref.get("kind") == "ClusterRole":
                cr = self.clusterroles.get(role_ref.get("name"))
                if not cr:
                    continue
                perms = self._extract_permissions(cr.get("rules", []))
                for subject in subjects:
                    identity_id = self._subject_to_id(subject, None)
                    record(identity_id, perms, None)

        # RoleBindings → namespace-scoped permissions
        for rb in self.rolebindings:
            role_ref = rb.get("roleRef", {})
            subjects = rb.get("subjects") or []
            binding_ns = rb["metadata"]["namespace"]

            if role_ref.get("kind") == "Role":
                role_key = f"{binding_ns}/{role_ref.get('name')}"
                role = self.roles.get(role_key)
                if not role:
                    continue
                perms = self._extract_permissions(role.get("rules", []))
                for subject in subjects:
                    identity_id = self._subject_to_id(subject, binding_ns)
                    record(identity_id, perms, binding_ns)

            elif role_ref.get("kind") == "ClusterRole":
                cr = self.clusterroles.get(role_ref.get("name"))
                if not cr:
                    continue
                # ClusterRole bound via RoleBinding = namespace-scoped
                perms = self._extract_permissions(cr.get("rules", []))
                for subject in subjects:
                    identity_id = self._subject_to_id(subject, binding_ns)
                    record(identity_id, perms, binding_ns)

        return identity_perms


# ============================================================
# Node builders
# ============================================================

def build_cluster_node(context_name):
    return [{
        "id": "cluster/cluster/default",
        "kinds": ["Cluster"],
        "properties": {
            "name": context_name,
        }
    }]


def build_external_actor_node():
    return [{
        "id": "cluster/externalactor/external",
        "kinds": ["ExternalActor"],
        "properties": {
            "name": "External Actor",
            "description": (
                "A threat actor with network-level visibility of the "
                "Kubernetes API server or Kubelet API"
            ),
        }
    }]


def build_node_nodes(pods, nodes_data):
    """
    Build Node nodes. Pod spec.nodeName is the source of truth for which
    nodes exist — ensures edges like podPrivileged always have a target even
    when the nodes API is inaccessible (e.g. namespace-scoped kubeconfig).
    Nodes returned by the API are fully enriched; any remaining nodes
    discovered only via pod specs are created as placeholders.
    """
    enriched = {}
    for node in nodes_data:
        meta = node["metadata"]
        name = meta["name"]
        labels = meta.get("labels", {})
        status = node.get("status", {})
        node_info = status.get("nodeInfo", {})

        is_control_plane = (
            "node-role.kubernetes.io/control-plane" in labels
            or "node-role.kubernetes.io/master" in labels
        )

        internal_ip = next(
            (a["address"] for a in status.get("addresses", [])
             if a.get("type") == "InternalIP"),
            ""
        )

        enriched[name] = {
            "id": nid(None, "node", name),
            "kinds": ["Node"],
            "properties": {
                "name": name,
                "controlplane": is_control_plane,
                "internalip": internal_ip,
                "kubeletversion": node_info.get("kubeletVersion", ""),
                "osimage": node_info.get("osImage", ""),
                "kernelversion": node_info.get("kernelVersion", ""),
                "containerruntime": node_info.get("containerRuntimeVersion", ""),
            }
        }

    # Synthesize placeholder nodes for any node seen in pod specs but not
    # returned by the nodes API (e.g. namespace-scoped access).
    for pod in pods:
        node_name = pod.get("spec", {}).get("nodeName", "")
        if node_name and node_name not in enriched:
            enriched[node_name] = {
                "id": nid(None, "node", node_name),
                "kinds": ["Node"],
                "properties": {
                    "name": node_name,
                    "controlplane": False,
                    "internalip": "",
                    "kubeletversion": "",
                    "osimage": "",
                    "kernelversion": "",
                    "containerruntime": "",
                    "placeholder": True,
                }
            }

    return list(enriched.values())


def build_pod_nodes(pods):
    nodes = []
    for pod in pods:
        meta = pod["metadata"]
        ns = meta["namespace"]
        name = meta["name"]
        spec = pod.get("spec", {})
        status = pod.get("status", {})

        nodes.append({
            "id": nid(ns, "pod", name),
            "kinds": ["Pod"],
            "properties": {
                "name": name,
                "namespace": ns,
                "nodename": spec.get("nodeName", ""),
                "serviceaccountname": spec.get("serviceAccountName", "default"),
                "phase": status.get("phase", ""),
                "hostpid": spec.get("hostPID", False),
                "hostnetwork": spec.get("hostNetwork", False),
                "hostipc": spec.get("hostIPC", False),
            }
        })
    return nodes


def build_container_nodes(pods):
    nodes = []
    for pod in pods:
        meta = pod["metadata"]
        ns = meta["namespace"]
        pod_name = meta["name"]
        spec = pod.get("spec", {})

        all_containers = (
            spec.get("containers", [])
            + spec.get("initContainers", [])
            + spec.get("ephemeralContainers", [])
        )

        for container in all_containers:
            cname = container["name"]
            sc = container.get("securityContext", {})

            nodes.append({
                "id": nid(ns, "container", f"{pod_name}/{cname}"),
                "kinds": ["Container"],
                "properties": {
                    "name": cname,
                    "namespace": ns,
                    "podname": pod_name,
                    "image": container.get("image", ""),
                    "privileged": sc.get("privileged", False),
                    "allowprivilegeescalation": sc.get("allowPrivilegeEscalation", True),
                    "readonlyrootfilesystem": sc.get("readOnlyRootFilesystem", False),
                    "runasuser": sc.get("runAsUser"),
                    "runasnonroot": sc.get("runAsNonRoot", False),
                }
            })
    return nodes


def build_service_nodes(services):
    nodes = []
    for svc in services:
        meta = svc["metadata"]
        ns = meta["namespace"]
        name = meta["name"]
        spec = svc.get("spec", {})

        raw_ports = spec.get("ports") or []
        port_strs = []
        for p in raw_ports:
            proto = p.get("protocol", "TCP")
            port_num = p.get("port", "")
            port_name = p.get("name", "")
            entry = f"{port_name}:{port_num}/{proto}" if port_name else f"{port_num}/{proto}"
            port_strs.append(entry)

        nodes.append({
            "id": nid(ns, "service", name),
            "kinds": ["Service"],
            "properties": {
                "name": name,
                "namespace": ns,
                "type": spec.get("type", "ClusterIP"),
                "clusterIP": spec.get("clusterIP", ""),
                "ports": ", ".join(port_strs) if port_strs else "",
                "externalips": spec.get("externalIPs", []),
                "selector": json.dumps(spec.get("selector") or {}),
            }
        })
    return nodes


def build_secret_nodes(secrets):
    nodes = []
    for secret in secrets:
        meta = secret["metadata"]
        ns = meta["namespace"]
        name = meta["name"]

        nodes.append({
            "id": nid(ns, "secret", name),
            "kinds": ["Secret"],
            "properties": {
                "name": name,
                "namespace": ns,
                "type": secret.get("type", "Opaque"),
            }
        })
    return nodes


def build_identity_nodes(serviceaccounts):
    """Build Identity nodes from ServiceAccount resources."""
    nodes = []
    for sa in serviceaccounts:
        meta = sa["metadata"]
        ns = meta["namespace"]
        name = meta["name"]

        nodes.append({
            "id": nid(ns, "serviceaccount", name),
            "kinds": ["Identity"],
            "properties": {
                "name": name,
                "namespace": ns,
                "kind": "ServiceAccount",
                "automounttoken": sa.get("automountServiceAccountToken", True),
            }
        })
    return nodes


def build_user_group_nodes(rolebindings, clusterrolebindings):
    """
    Discover User and Group identities from binding subjects.
    These are not enumerable directly via kubectl so are derived from bindings.
    """
    nodes = []
    seen = set()

    for binding in rolebindings + clusterrolebindings:
        for subject in (binding.get("subjects") or []):
            kind = subject.get("kind")
            name = subject.get("name", "")

            if kind == "User":
                node_id_str = nid(None, "user", name)
                if node_id_str not in seen:
                    seen.add(node_id_str)
                    nodes.append({
                        "id": node_id_str,
                        "kinds": ["Identity"],
                        "properties": {
                            "name": name,
                            "namespace": "",
                            "kind": "User",
                        }
                    })
            elif kind == "Group":
                node_id_str = nid(None, "group", name)
                if node_id_str not in seen:
                    seen.add(node_id_str)
                    nodes.append({
                        "id": node_id_str,
                        "kinds": ["Identity"],
                        "properties": {
                            "name": name,
                            "namespace": "",
                            "kind": "Group",
                        }
                    })
    return nodes


def build_volume_nodes(pods, pvcs, pvs):
    """
    Build Volume nodes from pod volume declarations.
    Resolves PVC → PV references to surface the underlying storage details.
    """
    nodes = []
    seen = set()

    # Build PVC → PV name map
    pvc_to_pv = {
        f"{pvc['metadata']['namespace']}/{pvc['metadata']['name']}": pvc.get("spec", {}).get("volumeName", "")
        for pvc in pvcs
    }
    pv_map = {pv["metadata"]["name"]: pv for pv in pvs}

    for pod in pods:
        meta = pod["metadata"]
        ns = meta["namespace"]
        pod_name = meta["name"]

        for volume in pod.get("spec", {}).get("volumes", []):
            vol_name = volume.get("name", "")
            vol_id = nid(ns, "volume", f"{pod_name}/{vol_name}")

            if vol_id in seen:
                continue
            seen.add(vol_id)

            # Determine volume type and notable source
            vol_type = "unknown"
            source = ""

            if "hostPath" in volume:
                vol_type = "hostPath"
                source = volume["hostPath"].get("path", "")
            elif "secret" in volume:
                vol_type = "secret"
                source = volume["secret"].get("secretName", "")
            elif "configMap" in volume:
                vol_type = "configMap"
                source = volume["configMap"].get("name", "")
            elif "persistentVolumeClaim" in volume:
                vol_type = "persistentVolumeClaim"
                claim_name = volume["persistentVolumeClaim"].get("claimName", "")
                pv_name = pvc_to_pv.get(f"{ns}/{claim_name}", "")
                source = f"{claim_name} -> {pv_name}" if pv_name else claim_name
                # Enrich with PV details if available
                if pv_name and pv_name in pv_map:
                    pv_spec = pv_map[pv_name].get("spec", {})
                    if "hostPath" in pv_spec:
                        source += f" (hostPath: {pv_spec['hostPath'].get('path', '')})"
                    elif "nfs" in pv_spec:
                        source += f" (nfs: {pv_spec['nfs'].get('server', '')}:{pv_spec['nfs'].get('path', '')})"
            elif "projected" in volume:
                vol_type = "projected"
                sources = [
                    list(s.keys())[0]
                    for s in volume["projected"].get("sources", [])
                    if s
                ]
                source = ", ".join(sources)
            elif "emptyDir" in volume:
                vol_type = "emptyDir"
            elif "nfs" in volume:
                vol_type = "nfs"
                source = f"{volume['nfs'].get('server', '')}:{volume['nfs'].get('path', '')}"
            elif "csi" in volume:
                vol_type = "csi"
                source = volume["csi"].get("driver", "")

            nodes.append({
                "id": vol_id,
                "kinds": ["Volume"],
                "properties": {
                    "name": vol_name,
                    "namespace": ns,
                    "podname": pod_name,
                    "volumetype": vol_type,
                    "source": source,
                }
            })
    return nodes


def build_role_nodes(roles, clusterroles):
    nodes = []
    for role in roles:
        meta = role["metadata"]
        ns = meta["namespace"]
        name = meta["name"]
        nodes.append({
            "id": nid(ns, "role", name),
            "kinds": ["Role"],
            "properties": {
                "name": name,
                "namespace": ns,
            }
        })
    for cr in clusterroles:
        meta = cr["metadata"]
        name = meta["name"]
        nodes.append({
            "id": nid(None, "clusterrole", name),
            "kinds": ["ClusterRole"],
            "properties": {
                "name": name,
            }
        })
    return nodes


def build_namespace_nodes(pods, services, secrets, serviceaccounts):
    """Derive Namespace nodes from collected namespaced resources."""
    namespaces = set()
    for items in [pods, services, secrets, serviceaccounts]:
        for item in items:
            ns = item["metadata"].get("namespace")
            if ns:
                namespaces.add(ns)
    return [
        {
            "id": nid(None, "namespace", ns),
            "kinds": ["Namespace"],
            "properties": {"name": ns},
        }
        for ns in sorted(namespaces)
    ]


def build_binding_nodes(rolebindings, clusterrolebindings):
    nodes = []
    for rb in rolebindings:
        meta = rb["metadata"]
        ns = meta["namespace"]
        name = meta["name"]
        role_ref = rb.get("roleRef", {})
        nodes.append({
            "id": nid(ns, "rolebinding", name),
            "kinds": ["RoleBinding"],
            "properties": {
                "name": name,
                "namespace": ns,
                "rolerefname": role_ref.get("name", ""),
                "rolerefkind": role_ref.get("kind", ""),
            }
        })
    for crb in clusterrolebindings:
        meta = crb["metadata"]
        name = meta["name"]
        role_ref = crb.get("roleRef", {})
        nodes.append({
            "id": nid(None, "clusterrolebinding", name),
            "kinds": ["ClusterRoleBinding"],
            "properties": {
                "name": name,
                "rolerefname": role_ref.get("name", ""),
                "rolerefkind": role_ref.get("kind", ""),
            }
        })
    return nodes


def build_imds_nodes(nodes_data):
    """Detect the cloud provider from node metadata and add an IMDS service node."""
    for node in nodes_data:
        labels = node.get("metadata", {}).get("labels", {})
        provider_id = node.get("spec", {}).get("providerID", "")
        label_str = json.dumps(labels)

        if provider_id.startswith("aws://") or "eks.amazonaws.com" in label_str:
            return [{
                "id": "cluster/imdsservice/aws-imds",
                "kinds": ["IMDSService"],
                "properties": {
                    "name": "AWS IMDS",
                    "provider": "AWS",
                    "endpoint": "http://169.254.169.254",
                    "description": (
                        "AWS Instance Metadata Service - reachable from any Pod. "
                        "Without IMDSv2 enforcement, credentials are obtainable via simple HTTP GET."
                    ),
                }
            }]
        elif provider_id.startswith("azure://") or "kubernetes.azure.com" in label_str:
            return [{
                "id": "cluster/imdsservice/azure-imds",
                "kinds": ["IMDSService"],
                "properties": {
                    "name": "Azure IMDS",
                    "provider": "Azure",
                    "endpoint": "http://169.254.169.254",
                    "description": (
                        "Azure Instance Metadata Service - reachable from any Pod. "
                        "Can be used to obtain managed identity tokens."
                    ),
                }
            }]
        elif provider_id.startswith("gce://") or "cloud.google.com" in label_str:
            return [{
                "id": "cluster/imdsservice/gcp-metadata",
                "kinds": ["IMDSService"],
                "properties": {
                    "name": "GCP Metadata Server",
                    "provider": "GCP",
                    "endpoint": "http://metadata.google.internal",
                    "description": (
                        "GCP Metadata Server - reachable from any Pod. "
                        "Can be used to obtain service account tokens and instance metadata."
                    ),
                }
            }]
    return []


# ============================================================
# Edge builders
# ============================================================

def make_edge(start_id, end_id, kind, properties=None):
    edge = {
        "start": {"value": start_id, "match_by": "id"},
        "end": {"value": end_id, "match_by": "id"},
        "kind": kind,
    }
    if properties:
        edge["properties"] = properties
    return edge


class EdgeBuilder:
    """Collects edges with built-in deduplication."""

    def __init__(self):
        self._edges = []
        self._seen = set()

    def add(self, start_id, end_id, kind, properties=None):
        key = (start_id, end_id, kind)
        if key not in self._seen:
            self._seen.add(key)
            self._edges.append(make_edge(start_id, end_id, kind, properties))

    def edges(self):
        return self._edges


def build_structural_edges(pods, services, rolebindings, clusterrolebindings, roles, clusterroles):
    """
    Build structural/non-RBAC edges:
    - entryPoint:             Service → Pod
    - podPrivileged:          Pod → Node
    - podHostPID:             Pod → Node
    - podHostNetwork:         Pod → Node
    - podHostIPC:             Pod → Node
    - compromiseServiceAccount: Pod → Identity
    - hasReadVolume:          Pod → Volume
    - hasWriteVolume:         Pod → Volume
    - bindsRole:              RoleBinding/ClusterRoleBinding → Role/ClusterRole
    """
    eb = EdgeBuilder()

    # Index roles and clusterroles by ID for existence checks
    role_id_set = {nid(r["metadata"]["namespace"], "role", r["metadata"]["name"]) for r in roles}
    cr_id_set = {nid(None, "clusterrole", cr["metadata"]["name"]) for cr in clusterroles}

    # --- entryPoint: Service → Pod ---
    pod_index = [
        (p["metadata"]["namespace"], p["metadata"]["name"], p["metadata"].get("labels", {}))
        for p in pods
    ]
    for svc in services:
        svc_meta = svc["metadata"]
        svc_ns = svc_meta["namespace"]
        selector = svc.get("spec", {}).get("selector")
        if not selector:
            continue
        svc_id = nid(svc_ns, "service", svc_meta["name"])
        for pod_ns, pod_name, pod_labels in pod_index:
            if pod_ns != svc_ns:
                continue
            if all(pod_labels.get(k) == v for k, v in selector.items()):
                eb.add(svc_id, nid(pod_ns, "pod", pod_name), "entryPoint")

    # --- Pod-level node escape edges and container edges ---
    for pod in pods:
        pod_meta = pod["metadata"]
        ns = pod_meta["namespace"]
        pod_name = pod_meta["name"]
        spec = pod.get("spec", {})
        pod_id = nid(ns, "pod", pod_name)
        k8s_node_name = spec.get("nodeName")

        if k8s_node_name:
            k8s_node_id = nid(None, "node", k8s_node_name)

            if spec.get("hostPID"):
                eb.add(pod_id, k8s_node_id, "podHostPID")
            if spec.get("hostNetwork"):
                eb.add(pod_id, k8s_node_id, "podHostNetwork")
            if spec.get("hostIPC"):
                eb.add(pod_id, k8s_node_id, "podHostIPC")

            # podPrivileged: any container in this pod running privileged
            all_containers = (
                spec.get("containers", [])
                + spec.get("initContainers", [])
                + spec.get("ephemeralContainers", [])
            )
            for container in all_containers:
                if container.get("securityContext", {}).get("privileged"):
                    eb.add(pod_id, k8s_node_id, "podPrivileged",
                           {"containername": container["name"]})
                    break  # one edge per pod is sufficient

        # --- compromiseServiceAccount: Pod → Identity ---
        sa_name = spec.get("serviceAccountName") or "default"
        sa_id = nid(ns, "serviceaccount", sa_name)
        automount = spec.get("automountServiceAccountToken", True)

        token_mounted = automount
        if not token_mounted:
            for vol in spec.get("volumes", []):
                for src in vol.get("projected", {}).get("sources", []):
                    if "serviceAccountToken" in src:
                        token_mounted = True
                        break
                if token_mounted:
                    break

        if token_mounted:
            eb.add(pod_id, sa_id, "compromiseServiceAccount")

        all_containers = (
            spec.get("containers", [])
            + spec.get("initContainers", [])
            + spec.get("ephemeralContainers", [])
        )

        # --- hasReadVolume / hasWriteVolume: Pod → Volume ---
        for container in all_containers:
            cname = container["name"]
            for vm in container.get("volumeMounts", []):
                vol_name = vm.get("name", "")
                vol_id = nid(ns, "volume", f"{pod_name}/{vol_name}")
                props = {"mountpath": vm.get("mountPath", ""), "containername": cname}
                if vm.get("readOnly", False):
                    eb.add(pod_id, vol_id, "hasReadVolume", props)
                else:
                    eb.add(pod_id, vol_id, "hasWriteVolume", props)

    # --- bindsRole: Binding → Role/ClusterRole ---
    for rb in rolebindings:
        rb_meta = rb["metadata"]
        rb_id = nid(rb_meta["namespace"], "rolebinding", rb_meta["name"])
        role_ref = rb.get("roleRef", {})

        if role_ref.get("kind") == "Role":
            target = nid(rb_meta["namespace"], "role", role_ref.get("name", ""))
            if target in role_id_set:
                eb.add(rb_id, target, "bindsRole")
        elif role_ref.get("kind") == "ClusterRole":
            target = nid(None, "clusterrole", role_ref.get("name", ""))
            if target in cr_id_set:
                eb.add(rb_id, target, "bindsRole")

    for crb in clusterrolebindings:
        crb_meta = crb["metadata"]
        crb_id = nid(None, "clusterrolebinding", crb_meta["name"])
        role_ref = crb.get("roleRef", {})

        if role_ref.get("kind") == "ClusterRole":
            target = nid(None, "clusterrole", role_ref.get("name", ""))
            if target in cr_id_set:
                eb.add(crb_id, target, "bindsRole")

    # --- unauthAPIAccess / unauthKubeletAccess: ExternalActor → Node ---
    return eb


def build_unauth_edges(nodes_data):
    """
    Build unauthAPIAccess and unauthKubeletAccess edges.
    Edges are created for all nodes with verified=false as these require
    manual confirmation. Future versions will attempt live verification.
    """
    eb = EdgeBuilder()
    external_id = "cluster/externalactor/external"
    unauth_props = {
        "verified": False,
        "note": "Requires manual verification - check --anonymous-auth flag",
    }

    for node in nodes_data:
        meta = node["metadata"]
        labels = meta.get("labels", {})
        name = meta["name"]
        node_id_str = nid(None, "node", name)

        is_control_plane = (
            "node-role.kubernetes.io/control-plane" in labels
            or "node-role.kubernetes.io/master" in labels
        )

        # All nodes have a Kubelet API
        eb.add(external_id, node_id_str, "unauthKubeletAccess", unauth_props)

        # Only control plane nodes host the API server
        if is_control_plane:
            eb.add(external_id, node_id_str, "unauthAPIAccess", unauth_props)

    return eb


def build_imds_edges(pods, imds_nodes):
    """
    Build accessIMDS edges: Container → IMDSService.

    Every container in the cluster can reach the cloud IMDS endpoint by
    default since 169.254.169.254 is a link-local address accessible from
    all Pods unless explicitly blocked. Edges are marked verified=false
    until network policy checks and IMDSv2 hop-limit detection are added.
    """
    eb = EdgeBuilder()

    if not imds_nodes:
        return eb

    imds_id = imds_nodes[0]["id"]
    imds_props = {
        "verified": False,
        "note": (
            "Network policy blocking and IMDSv2 hop-limit enforcement "
            "are not yet checked - treat as potential path"
        ),
    }

    for pod in pods:
        meta = pod["metadata"]
        ns = meta["namespace"]
        pod_name = meta["name"]
        eb.add(nid(ns, "pod", pod_name), imds_id, "accessIMDS", imds_props)

    return eb


def build_rbac_edges(identity_perms, pods, secrets, serviceaccounts):
    """
    Translate resolved RBAC permissions into direct Identity → resource edges.

    Pod-targeting edges are abstracted to namespace/cluster level to avoid
    per-pod fan-out on large clusters. If resourceNames is set in the RBAC
    rule the edge still targets the specific named resource(s).

    Identities with fullAccess (*/*) skip all other edge types — the cluster
    edge covers everything.

    Edges produced:
    - canExec, canAttach, canPortForward, canPatch, canCreate, canCreateEphemeral
    - secretsRead
    - canCreateToken
    - nodesProxyRCE
    - fullAccess
    - canBind, canEscalate
    - canImpersonate
    """
    eb = EdgeBuilder()

    all_pods = [(p["metadata"]["namespace"], p["metadata"]["name"]) for p in pods]
    all_secrets = [(s["metadata"]["namespace"], s["metadata"]["name"]) for s in secrets]
    all_sas = [(sa["metadata"]["namespace"], sa["metadata"]["name"]) for sa in serviceaccounts]
    cluster_id = "cluster/cluster/default"

    def match(actual, target):
        return actual == "*" or actual == target

    def ns_target(namespace):
        """Namespace node if scoped, cluster node if cluster-wide."""
        if namespace:
            return nid(None, "namespace", namespace)
        return cluster_id

    def scoped_pods(namespace):
        if namespace:
            return [(ns, n) for ns, n in all_pods if ns == namespace]
        return all_pods

    def scoped_secrets(namespace):
        if namespace:
            return [(ns, n) for ns, n in all_secrets if ns == namespace]
        return all_secrets

    def scoped_sas(namespace):
        if namespace:
            return [(ns, n) for ns, n in all_sas if ns == namespace]
        return all_sas

    # Pre-scan: identities with */* get a single fullAccess edge and nothing else
    full_access_identities = set()
    for identity_id, perms in identity_perms.items():
        for p in perms:
            if p["resource"] == "*" and p["verb"] == "*" and p.get("subresource") is None:
                full_access_identities.add(identity_id)
                break

    for identity_id in full_access_identities:
        eb.add(identity_id, cluster_id, "fullAccess")

    for identity_id, perms in identity_perms.items():
        if identity_id in full_access_identities:
            continue

        for p in perms:
            r = p["resource"]
            sub = p["subresource"]
            v = p["verb"]
            ns = p["namespace"]
            rnames = p.get("resource_names") or []
            target = ns_target(ns)

            def pod_targets():
                if rnames:
                    for pod_ns, pod_name in scoped_pods(ns):
                        if pod_name in rnames:
                            yield nid(pod_ns, "pod", pod_name)
                else:
                    yield target

            def secret_targets():
                if rnames:
                    for sec_ns, sec_name in scoped_secrets(ns):
                        if sec_name in rnames:
                            yield nid(sec_ns, "secret", sec_name)
                else:
                    yield target

            def sa_targets():
                if rnames:
                    for sa_ns, sa_name in scoped_sas(ns):
                        if sa_name in rnames:
                            yield nid(sa_ns, "serviceaccount", sa_name)
                else:
                    yield target

            # canExec
            if match(r, "pods") and sub == "exec" and match(v, "create"):
                for t in pod_targets():
                    eb.add(identity_id, t, "canExec")

            # canAttach
            if match(r, "pods") and sub == "attach" and match(v, "create"):
                for t in pod_targets():
                    eb.add(identity_id, t, "canAttach")

            # canPortForward
            if match(r, "pods") and sub == "portforward" and match(v, "create"):
                for t in pod_targets():
                    eb.add(identity_id, t, "canPortForward")

            # canCreateEphemeral
            if match(r, "pods") and sub == "ephemeralcontainers" and match(v, "update"):
                for t in pod_targets():
                    eb.add(identity_id, t, "canCreateEphemeral")

            # canPatch
            if match(r, "pods") and sub is None and (match(v, "patch") or match(v, "update")):
                for t in pod_targets():
                    eb.add(identity_id, t, "canPatch")

            # canCreate
            if match(r, "pods") and sub is None and match(v, "create"):
                for t in pod_targets():
                    eb.add(identity_id, t, "canCreate")

            # secretsRead
            if match(r, "secrets") and sub is None and (match(v, "get") or match(v, "list")):
                for t in secret_targets():
                    eb.add(identity_id, t, "secretsRead")

            # canCreateToken: create on serviceaccounts/token (TokenRequest API)
            if match(r, "serviceaccounts") and sub == "token" and match(v, "create"):
                for t in sa_targets():
                    eb.add(identity_id, t, "canCreateToken")

            # nodesProxyRCE → single cluster edge
            if match(r, "nodes") and sub == "proxy" and match(v, "get"):
                eb.add(identity_id, cluster_id, "nodesProxyRCE")

            # canBind: rolebindings → namespace, clusterrolebindings → cluster
            if match(r, "rolebindings") and (match(v, "create") or match(v, "patch") or match(v, "update")):
                eb.add(identity_id, target, "canBind")
            if match(r, "clusterrolebindings") and (match(v, "create") or match(v, "patch") or match(v, "update")):
                eb.add(identity_id, cluster_id, "canBind")

            # canEscalate: roles → namespace, clusterroles → cluster
            if match(r, "roles") and match(v, "escalate"):
                eb.add(identity_id, target, "canEscalate")
            if match(r, "clusterroles") and match(v, "escalate"):
                eb.add(identity_id, cluster_id, "canEscalate")

            # canImpersonate → namespace/cluster with resource type as context
            if match(v, "impersonate") and match(r, "serviceaccounts"):
                eb.add(identity_id, target, "canImpersonate", {"resource": "serviceaccounts"})
            if match(v, "impersonate") and (match(r, "users") or match(r, "groups")):
                eb.add(identity_id, cluster_id, "canImpersonate", {"resource": r})

    return eb


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "ClusterHound - Kubernetes attack path collector for BloodHound.\n"
            "Collects cluster data from the current kubeconfig context and\n"
            "outputs an OpenGraph JSON file for ingestion into BloodHound CE."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-o", "--output",
        default="clusterhound.json",
        help="Output file path (default: clusterhound.json)",
    )
    parser.add_argument(
        "-n", "--namespace",
        default=None,
        metavar="NAMESPACE",
        help="Collect only resources from a specific namespace (default: cluster-wide). "
             "Node nodes are synthesized from pod specs when the nodes API is inaccessible.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    # Verify kubectl is available and reachable
    context_name = kubectl_raw("config", "current-context")
    if not context_name:
        logging.error("kubectl is not available or no current context is set.")
        sys.exit(1)
    logging.info(f"Target context: {context_name}")

    # ── Collect ──────────────────────────────────────────────
    data = collect_all(namespace=args.namespace)

    pods                = data["pods"]
    services            = data["services"]
    secrets             = data["secrets"]
    serviceaccounts     = data["serviceaccounts"]
    roles               = data["roles"]
    rolebindings        = data["rolebindings"]
    clusterroles        = data["clusterroles"]
    clusterrolebindings = data["clusterrolebindings"]
    nodes_k8s           = data["nodes"]
    pvcs                = data["persistentvolumeclaims"]
    pvs                 = data["persistentvolumes"]

    # ── Build nodes ───────────────────────────────────────────
    logging.info("Building graph nodes...")

    imds_nodes = build_imds_nodes(nodes_k8s)

    graph_nodes = (
        build_cluster_node(context_name)
        + build_external_actor_node()
        + build_node_nodes(pods, nodes_k8s)
        + build_namespace_nodes(pods, services, secrets, serviceaccounts)
        + build_pod_nodes(pods)
        + build_service_nodes(services)
        + build_secret_nodes(secrets)
        + build_identity_nodes(serviceaccounts)
        + build_user_group_nodes(rolebindings, clusterrolebindings)
        + build_volume_nodes(pods, pvcs, pvs)
        + build_role_nodes(roles, clusterroles)
        + build_binding_nodes(rolebindings, clusterrolebindings)
        + imds_nodes
    )
    logging.info(f"Built {len(graph_nodes)} nodes")

    # ── Resolve RBAC ──────────────────────────────────────────
    logging.info("Resolving RBAC...")
    resolver = RBACResolver(roles, clusterroles, rolebindings, clusterrolebindings)
    identity_perms = resolver.resolve()
    logging.info(f"Resolved permissions for {len(identity_perms)} identities")

    # ── Build edges ───────────────────────────────────────────
    logging.info("Building graph edges...")

    structural_eb = build_structural_edges(
        pods, services, rolebindings, clusterrolebindings, roles, clusterroles
    )
    unauth_eb = build_unauth_edges(nodes_k8s)
    imds_eb = build_imds_edges(pods, imds_nodes)
    rbac_eb = build_rbac_edges(identity_perms, pods, secrets, serviceaccounts)

    graph_edges = (
        structural_eb.edges()
        + unauth_eb.edges()
        + imds_eb.edges()
        + rbac_eb.edges()
    )
    logging.info(f"Built {len(graph_edges)} edges")

    # ── Normalise node properties ──────────────────────────────
    # objectid: required by BloodHound CE's ingest worker as the internal
    #           node identifier — without it nodes are silently discarded.
    # name:     BloodHound convention is UPPERCASE for search/dedup.
    # displayname: human-readable label shown in the UI.
    for node in graph_nodes:
        props = node.setdefault("properties", {})

        # objectid must match the node id exactly
        props.setdefault("objectid", node["id"])

        # Uppercase the primary name used for search
        if "name" in props:
            props["name"] = props["name"].upper()

        # displayname: "Kind name" in original casing for readability
        if "displayname" not in props:
            kind = node["kinds"][0] if node.get("kinds") else "Node"
            raw_name = props.get("objectid", node["id"])
            props["displayname"] = f"{kind} {raw_name}"

    # ── Strip null property values (OpenGraph schema rejects null) ────
    for node in graph_nodes:
        if "properties" in node:
            node["properties"] = clean_props(node["properties"])
    for edge in graph_edges:
        if "properties" in edge:
            edge["properties"] = clean_props(edge["properties"])

    # ── Assemble output ───────────────────────────────────────
    output = {
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges,
        },
        "metadata": {
            "source_kind": "ClusterHound",
            "context": context_name,
            "collected_at": datetime.now(timezone.utc).isoformat(),
        }
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)

    logging.info(f"Output written to: {args.output}")
    logging.info(
        f"Summary: {len(graph_nodes)} nodes | {len(graph_edges)} edges"
    )


if __name__ == "__main__":
    main()
