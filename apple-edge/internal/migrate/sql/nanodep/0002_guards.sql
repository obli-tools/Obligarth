-- Guard constraint of apple-edge on the upstream NanoDEP table. OAuth
-- secrets and token PKI keys live encrypted in apple_edge.ade_tokens; the
-- upstream table only keeps non-secret state (cursor). The upstream CHECK
-- on tokenpki_key_pem only looks at its first five characters.
ALTER TABLE nanodep.dep_names ADD CONSTRAINT obligarth_no_clear_secrets CHECK (
    consumer_key IS NULL AND consumer_secret IS NULL
    AND access_token IS NULL AND access_secret IS NULL
    AND tokenpki_key_pem IS NULL AND tokenpki_staging_key_pem IS NULL);
