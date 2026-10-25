# Azure Management Groups Onboarding Guide

This document describes how to securely onboard multiple Azure subscriptions across Azure Management Groups into the Cloud Security Compliance Dashboard.

## Architecture & Security Model

Production onboarding requires:
1. Azure Workload Identity Federation / Service Principals with Federated Credentials (OIDC).
2. Elimination of long-lived client secret passwords.
3. Built-in `Reader` role assigned at the **Management Group** root or target management group scope.

## Multi-Subscription Deployment via Management Groups

1. **Register the Azure AD (Entra ID) Application:**
   - In the Microsoft Entra ID admin center, create an App Registration (e.g., `CloudSec-Posture-Reader`).
   - Configure **Federated Credentials** under **Certificates & Secrets** specifying your CloudSec platform issuer and subject identifier.

2. **Assign Reader Role at Management Group Scope:**
   - Navigate to **Management Groups** in the Azure Portal.
   - Select your target Management Group (e.g., `Tenant Root Group` or `Production`).
   - Under **Access control (IAM)**, select **Add role assignment**.
   - Select the built-in **Reader** role.
   - Assign access to the `CloudSec-Posture-Reader` Service Principal.
   - Any current or future subscription placed under this Management Group automatically inherits `Reader` permissions.

3. **Register Resource Providers:**
   Ensure each member subscription has enabled the following resource providers:
   - `Microsoft.Storage`
   - `Microsoft.Network`
   - `Microsoft.KeyVault`
   - `Microsoft.Authorization`

4. **Connect in CloudSec Dashboard:**
   - Provide `tenant_id`, `client_id`, and primary `subscription_id`.
   - Submit federated credential token or subject assertion.

## Security Verification

CloudSec validates:
- Azure Resource Manager token acquisition via workload identity.
- Read access to subscriptions under the Management Group.
- Verification that no client secrets or passwords are stored in the database.
- Records the onboarding in the immutable audit log.

