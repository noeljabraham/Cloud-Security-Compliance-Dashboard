# Database migrations

Add SQLx migrations here as `YYYYMMDDHHMMSS_description.sql`. The initial domain schema is in
`20260101000000_core_domain.sql`.

The schema stores tenant-owned normalized data. Provider secrets are never represented by a
column. Optional raw provider payloads use encrypted bytea columns and must be encrypted by the
application before insertion; the database does not receive encryption keys.
