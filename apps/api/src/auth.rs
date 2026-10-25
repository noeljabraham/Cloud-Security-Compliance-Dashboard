use axum::{
    Json,
    http::{HeaderMap, StatusCode},
};
use cloudsec_domain::{AuthUser, Id, UserRole};
use serde_json::{Value, json};
use uuid::Uuid;

pub const DEFAULT_ORG_ID: &str = "00000000-0000-0000-0000-000000000001";
pub const DEFAULT_USER_ID: &str = "00000000-0000-0000-0000-000000000002";

pub fn extract_auth_user(headers: &HeaderMap) -> AuthUser {
    let mut role = UserRole::Admin; // default for local development
    let mut email = "security-admin@cloudsec.local".to_string();
    let mut user_id = Uuid::parse_str(DEFAULT_USER_ID).unwrap();
    let mut org_id = Uuid::parse_str(DEFAULT_ORG_ID).unwrap();

    // 1. Check Authorization: Bearer <token>
    if let Some(auth_val) = headers.get("authorization") {
        if let Ok(auth_str) = auth_val.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ").map(str::trim) {
                // If token contains simulated or decoded claims
                if token.contains("role=viewer") || token == "viewer" || token == "viewer-token" {
                    role = UserRole::Viewer;
                    email = "viewer@cloudsec.local".to_string();
                } else if token.contains("role=auditor")
                    || token == "auditor"
                    || token == "auditor-token"
                {
                    role = UserRole::Auditor;
                    email = "auditor@cloudsec.local".to_string();
                } else if token.contains("role=engineer")
                    || token == "engineer"
                    || token == "engineer-token"
                {
                    role = UserRole::SecurityEngineer;
                    email = "engineer@cloudsec.local".to_string();
                } else if token.contains("role=admin") || token == "admin" || token == "admin-token"
                {
                    role = UserRole::Admin;
                    email = "admin@cloudsec.local".to_string();
                }

                // Check for custom org in token (e.g. org=...)
                for part in token.split(',') {
                    if let Some(val) = part.strip_prefix("org=") {
                        if let Ok(parsed) = Uuid::parse_str(val.trim()) {
                            org_id = parsed;
                        }
                    }
                }
            }
        }
    }

    // 2. Explicit headers take precedence (for easy testing and reverse proxy propagation)
    if let Some(r_val) = headers.get("x-user-role") {
        if let Ok(r_str) = r_val.to_str() {
            match r_str.to_lowercase().as_str() {
                "viewer" => role = UserRole::Viewer,
                "auditor" => role = UserRole::Auditor,
                "security_engineer" | "engineer" => role = UserRole::SecurityEngineer,
                "admin" => role = UserRole::Admin,
                _ => {}
            }
        }
    }

    if let Some(e_val) = headers.get("x-user-email") {
        if let Ok(e_str) = e_val.to_str() {
            email = e_str.to_string();
        }
    }

    if let Some(u_val) = headers.get("x-user-id") {
        if let Ok(u_str) = u_val.to_str() {
            if let Ok(parsed) = Uuid::parse_str(u_str) {
                user_id = parsed;
            }
        }
    }

    if let Some(o_val) = headers.get("x-organization-id") {
        if let Ok(o_str) = o_val.to_str() {
            if let Ok(parsed) = Uuid::parse_str(o_str) {
                org_id = parsed;
            }
        }
    }

    AuthUser {
        user_id,
        email,
        role,
        organization_id: org_id,
    }
}

pub fn check_permission(
    user: &AuthUser,
    allowed_roles: &[UserRole],
) -> Result<(), (StatusCode, Json<Value>)> {
    if allowed_roles.contains(&user.role) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": {
                    "code": "forbidden",
                    "message": format!("User role '{:?}' is not authorized to perform this action", user.role),
                    "allowed_roles": allowed_roles.iter().map(|r| format!("{r:?}")).collect::<Vec<_>>()
                }
            })),
        ))
    }
}

pub fn check_tenant_isolation(
    user: &AuthUser,
    entity_org_id: Id,
) -> Result<(), (StatusCode, Json<Value>)> {
    if user.organization_id == entity_org_id {
        Ok(())
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": {
                    "code": "not_found",
                    "message": "The requested resource was not found in the current organization"
                }
            })),
        ))
    }
}
