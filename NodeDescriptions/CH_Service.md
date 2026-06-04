# CH_Service

## Overview

A Kubernetes Service. Source of `CH_entryPoint` edges to Pods whose labels match the Service selector, representing potential initial access paths into the cluster.

## Scope

Namespaced

## Properties

| Property | Description |
|----------|-------------|
| name | Service name |
| namespace | Namespace the Service belongs to |
| type | Service type: ClusterIP, NodePort, LoadBalancer, or ExternalName |
| Cluster IP | Assigned cluster-internal IP address |
| ports | Comma-separated port definitions (e.g. `http:80/TCP, https:443/TCP`) |
| External IPs | External IP addresses assigned to the Service (if any) |
| selector | Label selector as a JSON string used to match target Pods |
