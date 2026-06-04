# CH_Node

## Overview

A Kubernetes worker or control plane node. Enriched with OS, kernel, kubelet version and internal IP where the nodes API is accessible. Synthesised as a placeholder from `spec.nodeName` on Pod specs when the nodes API is inaccessible.

## Scope

Cluster

## Properties

| Property | Description |
|----------|-------------|
| name | Node hostname |
| Control plane | `true` if the node carries the `control-plane` or `master` role label |
| Internal IP | Node's internal IP address |
| Kubelet version | Kubelet version string (e.g. `v1.29.0`) |
| OS image | Operating system image (e.g. `Ubuntu 22.04.3 LTS`) |
| Kernel version | Linux kernel version |
| Container runtime | Container runtime and version (e.g. `containerd://1.7.0`) |
| placeholder | `true` only when the node was synthesised from a Pod's `spec.nodeName` because the nodes API was inaccessible |
