# Release verification

Logwizz releases publish two Linux x86-64 binaries, SHA-256 checksums, and a CycloneDX JSON SBOM for each binary. GitHub Artifact Attestations bind the published binaries to their build provenance and SBOMs.

These controls answer different questions:

- **SHA-256** detects accidental corruption when the checksum file is trusted.
- **Build provenance** binds an artifact digest to the source repository, revision and GitHub Actions workflow identity.
- **SBOM** inventories the Rust package and dependency graph used to build each binary. It is not proof that the dependencies are benign or that the build is vulnerability-free.

## Verify a release

Install a recent GitHub CLI with the attestation command, download the binary, checksum file and SBOM from the same [GitHub Release](https://github.com/mycaravam-crypto/logwizz/releases), then run:

```sh
v=X.Y.Z
base="https://github.com/mycaravam-crypto/logwizz/releases/download/v$v"

curl -fLO "$base/logwizz-v$v-linux-x64"
curl -fLO "$base/logwizz-notify-v$v-linux-x64"
curl -fLO "$base/SHA256SUMS.txt"
curl -fLO "$base/logwizz-sbom.cdx.json"
curl -fLO "$base/logwizz-notify-sbom.cdx.json"

sha256sum --ignore-missing -c SHA256SUMS.txt

gh attestation verify "logwizz-v$v-linux-x64" \
  --repo mycaravam-crypto/logwizz \
  --signer-workflow mycaravam-crypto/logwizz/.github/workflows/release.yml

gh attestation verify "logwizz-notify-v$v-linux-x64" \
  --repo mycaravam-crypto/logwizz \
  --signer-workflow mycaravam-crypto/logwizz/.github/workflows/release.yml
```

The attestation verification checks the expected repository and release workflow identity. Do not treat a successful checksum check alone as authentication if the binary and checksum were obtained from the same untrusted source.

The SBOM files are CycloneDX JSON and describe the Cargo binary targets and their dependency graph for the release target. Review them with an SBOM viewer or ingest them into your dependency inventory. Their contents depend on the locked dependency graph and enabled target/features; an SBOM does not establish that a component is safe.

## Workflow security boundaries

- The build job has no artifact-publishing or attestation permissions.
- Only the publish job receives release-write and short-lived OIDC/attestation permissions.
- The workflow pins third-party actions to commit SHAs.
- No long-lived signing key or repository secret is introduced.
- SHA-256 checksums remain available alongside provenance and SBOMs.
