use cloudsec_domain::CoverageGapReason;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScannerError {
    AuthenticationFailed(String),
    PermissionDenied {
        service: String,
        resource: Option<String>,
        action: String,
    },
    Throttling {
        message: String,
        retry_after_ms: Option<u64>,
    },
    UnsupportedRegionService {
        region: String,
        service: String,
    },
    TransientNetwork(String),
    Timeout(String),
    Cancelled,
    Internal(String),
}

impl ScannerError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Throttling { .. } | Self::TransientNetwork(_))
    }

    pub fn is_permission_denied(&self) -> bool {
        matches!(self, Self::PermissionDenied { .. })
    }

    pub fn to_coverage_gap_reason(&self) -> Option<CoverageGapReason> {
        match self {
            Self::PermissionDenied { .. } => Some(CoverageGapReason::PermissionDenied),
            Self::Throttling { .. } => Some(CoverageGapReason::Throttled),
            Self::UnsupportedRegionService { .. } => Some(CoverageGapReason::UnsupportedRegion),
            Self::Timeout(_) => Some(CoverageGapReason::Timeout),
            Self::Internal(_) | Self::TransientNetwork(_) => Some(CoverageGapReason::InternalError),
            Self::AuthenticationFailed(_) | Self::Cancelled => None,
        }
    }
}

impl fmt::Display for ScannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed(msg) => write!(f, "authentication failed: {msg}"),
            Self::PermissionDenied {
                service,
                resource,
                action,
            } => {
                if let Some(res) = resource {
                    write!(
                        f,
                        "permission denied for action '{action}' on service '{service}', resource '{res}'"
                    )
                } else {
                    write!(
                        f,
                        "permission denied for action '{action}' on service '{service}'"
                    )
                }
            }
            Self::Throttling {
                message,
                retry_after_ms,
            } => {
                if let Some(delay) = retry_after_ms {
                    write!(f, "rate limit throttled ({message}), retry after {delay}ms")
                } else {
                    write!(f, "rate limit throttled: {message}")
                }
            }
            Self::UnsupportedRegionService { region, service } => {
                write!(f, "service '{service}' is unsupported in region '{region}'")
            }
            Self::TransientNetwork(msg) => write!(f, "transient network error: {msg}"),
            Self::Timeout(msg) => write!(f, "operation timed out: {msg}"),
            Self::Cancelled => write!(f, "scan operation was cancelled"),
            Self::Internal(msg) => write!(f, "internal scanner error: {msg}"),
        }
    }
}

impl std::error::Error for ScannerError {}
