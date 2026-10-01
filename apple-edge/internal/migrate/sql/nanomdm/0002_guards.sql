-- Guard constraints of apple-edge on the upstream NanoMDM tables.

-- Namespaced enrollment ids everywhere: '<16-char tenant key>_...'. If an
-- upstream release stopped deriving ids from the namespaced message, writes
-- would fail loudly instead of mixing two tenants.
ALTER TABLE nanomdm.devices ADD CONSTRAINT obligarth_ns_id
    CHECK (id ~ '^[a-km-np-z2-9]{16}_');
ALTER TABLE nanomdm.enrollments ADD CONSTRAINT obligarth_ns_id
    CHECK (id ~ '^[a-km-np-z2-9]{16}_' AND device_id ~ '^[a-km-np-z2-9]{16}_');
ALTER TABLE nanomdm.users ADD CONSTRAINT obligarth_ns_id
    CHECK (id ~ '^[a-km-np-z2-9]{16}_' AND device_id ~ '^[a-km-np-z2-9]{16}_');
ALTER TABLE nanomdm.enrollment_queue ADD CONSTRAINT obligarth_ns_id
    CHECK (id ~ '^[a-km-np-z2-9]{16}_');
ALTER TABLE nanomdm.command_results ADD CONSTRAINT obligarth_ns_id
    CHECK (id ~ '^[a-km-np-z2-9]{16}_');
ALTER TABLE nanomdm.cert_auth_associations ADD CONSTRAINT obligarth_ns_id
    CHECK (id ~ '^[a-km-np-z2-9]{16}_');

-- No protocol secret in clear in the upstream tables. The token_update test
-- is literal: it is a last-resort net, the real control being the storage
-- wrapper that strips the UnlockToken and re-serialises the plist.
ALTER TABLE nanomdm.devices ADD CONSTRAINT obligarth_no_clear_secrets CHECK (
    unlock_token IS NULL
    AND bootstrap_token_b64 IS NULL
    AND (token_update IS NULL OR strpos(token_update, '<key>UnlockToken</key>') = 0));

-- Push certificates live in apple_edge.push_certs (encrypted key).
ALTER TABLE nanomdm.push_certs ADD CONSTRAINT obligarth_unused CHECK (false);
