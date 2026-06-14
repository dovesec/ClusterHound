# CH_IMDSService

## Overview

Represents the cloud provider instance metadata endpoint. Detected from node `spec.providerID` and labels. Supports AWS, Azure, and GCP. Target of `CH_accessIMDS` edges from Nodes.

## Scope

Cluster

## Properties

| Property | Description |
|----------|-------------|
| name | Service name (e.g. `AWS IMDS`, `Azure IMDS`, `GCP Metadata Server`) |
| provider | Cloud provider: `AWS`, `Azure`, or `GCP` |
| endpoint | Metadata endpoint URL (e.g. `http://169.254.169.254`) |
| description | Human-readable description of the service and its security implications |
