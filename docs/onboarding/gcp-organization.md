# GCP Organization & Multi-Project Onboarding Guide

This document describes how to securely onboard multiple Google Cloud Platform (GCP) projects across an entire GCP Organization or Folder.

## Architecture & Security Model

Production onboarding requires:
1. **Workload Identity Federation**: Eliminates downloaded service account JSON private keys.
2. Short-lived token exchange and Service Account Impersonation via `iamcredentials.googleapis.com`.
3. Organization or Folder-level role binding with least-privilege `roles/viewer` or a custom posture-reading role.

## Setup Steps

1. **Create Workload Identity Pool and Provider:**
   ```bash
   gcloud iam workload-identity-pools create "cloudsec-pool" \
       --location="global" \
       --description="Pool for CloudSec compliance scanner"

   gcloud iam workload-identity-pools providers create-oidc "cloudsec-provider" \
       --workload-identity-pool="cloudsec-pool" \
       --location="global" \
       --issuer-uri="https://cloudsec.internal" \
       --attribute-mapping="google.subject=assertion.sub"
   ```

2. **Create a Centralized Service Account:**
   ```bash
   gcloud iam service-accounts create "cloudsec-reader" \
       --display-name="CloudSec Read-Only Posture Reader"
   ```

3. **Grant Organization/Folder-Level Read Access:**
   ```bash
   # Assign Viewer role at the organization level
   gcloud organizations add-iam-policy-binding "YOUR_ORGANIZATION_ID" \
       --member="serviceAccount:cloudsec-reader@YOUR_ADMIN_PROJECT.iam.gserviceaccount.com" \
       --role="roles/viewer"
   ```

4. **Allow Workload Identity Impersonation:**
   ```bash
   gcloud iam service-accounts add-iam-policy-binding \
       "cloudsec-reader@YOUR_ADMIN_PROJECT.iam.gserviceaccount.com" \
       --role="roles/iam.workloadIdentityUser" \
       --member="principalSet://iam.googleapis.com/projects/YOUR_PROJECT_NUMBER/locations/global/workloadIdentityPools/cloudsec-pool/*"
   ```

5. **Register in CloudSec Dashboard:**
   - Provider: `GCP`
   - Project ID: `YOUR_ADMIN_PROJECT` (or target project)
   - Workload Identity Pool: `projects/YOUR_PROJECT_NUMBER/locations/global/workloadIdentityPools/cloudsec-pool`
   - Service Account Email: `cloudsec-reader@YOUR_ADMIN_PROJECT.iam.gserviceaccount.com`

## Security Verification

CloudSec verifies:
- Token exchange against the Workload Identity Pool.
- Successful service account impersonation without stored JSON keys.
- Read access to Cloud Storage, Resource Manager, Compute Networks/Firewalls, and Cloud Logging.
- Immutable audit logging of connection registration and verification.

