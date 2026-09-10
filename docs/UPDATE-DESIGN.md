# Release and update trust

The initial `opengate update` command refuses to download or run unsigned binaries. Normal installation uses an explicitly obtained package; public release signing and update delivery are a separate release gate.

An enabled updater must use a signed manifest containing the product name, protocol-compatible version, target OS/architecture, artifact SHA-256, exact download URL, build provenance and an expiry. A public verification key is distributed through an independently authenticated installation/package channel; signing keys stay outside the source tree. Verify the manifest signature before trusting its fields, then verify the downloaded artifact's size and digest before installation. Reject downgrade, expired manifests, unexpected hosts/targets and untrusted key rotation.

Use a maintained signed-update framework such as TUF when implementation begins. Key rotation must be authorized by the current trusted metadata, include expiry/revocation handling, and provide an operator recovery procedure. TLS alone does not authorize execution of a release.

Installing an update must preserve the protected identity, trust database, configuration and resumable-transfer state. Stop through the normal service manager, stage the new executable, verify it, replace atomically where supported, and retain a verified rollback artifact. Database migrations are numbered and must not silently erase trust or permit running old software against a newer incompatible schema.

Automatic checks and automatic installation are independently disabled by default until a release owner configures this trust chain. The current repository has no embedded signing private key and does not claim a working signed updater.
