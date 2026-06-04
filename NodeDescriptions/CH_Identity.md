# CH_Identity

## Overview

Represents a ServiceAccount, User, or Group. ServiceAccounts are collected from the API; Users and Groups are discovered dynamically from binding subjects. Source of all RBAC-derived attack edges.

## Scope

Namespaced / Cluster

## Properties

| Property | Description |
|----------|-------------|
| name | Identity name |
| namespace | Namespace for ServiceAccounts; empty string for Users and Groups |
| kind | Identity type: `ServiceAccount`, `User`, or `Group` |
| Automount token | Whether the service account token is automatically mounted (ServiceAccount only) |
