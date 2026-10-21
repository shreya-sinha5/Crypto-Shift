# Legacy Cryptographic Code Database

This directory contains a curated benchmark suite of legacy C/C++ cryptographic implementations representing pre-PQC (Post-Quantum Cryptography) patterns commonly found in enterprise, embedded, and infrastructure systems.

These patterns are detected by **CryptoShift's C/C++ Parser**, indexed into the **Legacy Code Database** (`legacy_crypto.db`), and exportable to **SARIF 2.1.0** and **CycloneDX 1.6 CBOM**.

---

## 📁 Structure

```
demo/legacy_code/
├── include/
│   └── legacy_crypto.h       # Shared API definitions for legacy primitives
└── src/
    ├── key_service.c         # RSA-2048 keypair generation & PKCS#1 v1.5 encryption
    ├── signature_service.c   # ECDSA P-256 and RSA-SHA256 digital signatures
    ├── tls_session.c         # AES-256-CBC, ECDH P-256, and legacy TLS cipher suites
    ├── dh_exchange.c         # Classic Diffie-Hellman (MODP-2048) & ECDH P-521 key exchange
    └── hash_utils.c          # Broken/deprecated hashes (MD5, SHA-1, HMAC-MD5, HMAC-SHA1)
```

---

## 🎯 Target Vulnerabilities & PQC Migration Targets

| File | Legacy Primitive | Risk / Vulnerability | PQC Replacement (NIST) |
|---|---|---|---|
| `key_service.c` | RSA-2048 (PKCS#1 v1.5) | Shor's algorithm, Bleichenbacher attack | **ML-KEM** (FIPS 203 / Kyber) |
| `signature_service.c` | ECDSA (P-256), RSA-SHA256 | Shor's algorithm (discrete log / factoring) | **ML-DSA** (FIPS 204 / Dilithium) |
| `tls_session.c` | AES-256-CBC, ECDH P-256 | Unauthenticated CBC mode, broken key exchange | **AES-256-GCM**, **ML-KEM Hybrid** |
| `dh_exchange.c` | DH MODP-2048, ECDH P-521 | Shor's algorithm (finite field / elliptic curve discrete log) | **ML-KEM-768 / X25519 Hybrid** |
| `hash_utils.c` | MD5, SHA-1, HMAC-MD5 | Collision attacks (MD5 broken, SHA-1 deprecated) | **SHA-256 / SHA-3 / SHAKE** |

---

## 🛠️ CLI Usage

### 1. Scan Legacy Code into Database
```bash
# Scan directory and generate SARIF + CycloneDX CBOM
cryptoshift db scan demo/legacy_code \
  --repo my-legacy-repo \
  --db legacy_crypto.db \
  --sarif results.sarif \
  --cbom cbom.json
```

### 2. Query Findings
```bash
# List all findings
cryptoshift db list --db legacy_crypto.db

# Filter by algorithm
cryptoshift db list --db legacy_crypto.db --algo RSA

# Filter by severity
cryptoshift db list --db legacy_crypto.db --severity error
```

### 3. View Summary Metrics
```bash
cryptoshift db summary --db legacy_crypto.db
```

### 4. Export Reports
```bash
# Export to SARIF (GitHub Code Scanning compatible)
cryptoshift db export results.sarif --format sarif --db legacy_crypto.db

# Export to CycloneDX 1.6 CBOM
cryptoshift db export cbom.json --format cbom --db legacy_crypto.db

# Export to CryptoShift Enriched CBOM format
cryptoshift db export enriched.json --format enriched --db legacy_crypto.db
```

---

## 🔄 GitHub Actions Integration

The workflow [`.github/workflows/legacy-code-scan.yml`](../../.github/workflows/legacy-code-scan.yml) runs automatically on changes to `demo/legacy_code/`. It:
1. Executes `cryptoshift db scan`.
2. Uploads `results.sarif` to **GitHub Code Scanning** (Security tab alerts).
3. Archives `legacy_crypto.db` and CBOM files as workflow artifacts.
4. Posts an automated Markdown summary to the GitHub Actions Job Summary.
