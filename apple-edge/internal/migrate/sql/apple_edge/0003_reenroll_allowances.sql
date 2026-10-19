-- apple_edge schema, step 3: re-enrollment allowances (decision of the owners of
-- 19/10/2026 on AE-C0-R2bis and MDM-B2-R13, option C). An Authenticate without
-- ADE proof whose identifier is active in the same tenant under the same kind,
-- presented with another identity certificate, is refused unless the brain
-- allowed the re-enrollment of that identifier (the console's "Allow the
-- re-enrollment" on the device record). The allowance is consumed by the
-- Authenticate it lets through; it expires after 24 hours at most.

CREATE TABLE apple_edge.reenroll_allowances (
    tenant_key   text        NOT NULL REFERENCES apple_edge.tenants (key),
    id_kind      text        NOT NULL CHECK (id_kind IN ('udid', 'enrollment_id')),
    raw_id       text        NOT NULL,
    expires_at   timestamptz NOT NULL,
    request_id   text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_key, id_kind, raw_id)
);
CREATE INDEX reenroll_allowances_expires ON apple_edge.reenroll_allowances (expires_at);
