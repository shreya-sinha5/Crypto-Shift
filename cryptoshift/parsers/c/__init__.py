"""C/C++ parser adapter — detects legacy cryptographic API calls.

Scans C/C++ source files using regex-based pattern matching against
known OpenSSL, mbedTLS, Botan, and libgcrypt function signatures.
Produces SARIF 2.1.0 output (the legacy_db storage format).

Supported libraries:
  - OpenSSL  (RSA_*, AES_*, ECDSA_*, DH_*, SHA*, MD5*, HMAC, EVP_*)
  - mbedTLS  (mbedtls_rsa_*, mbedtls_ecdsa_*, mbedtls_aes_*, ...)
  - Botan    (Botan::RSA_*, Botan::ECDSA_*, Botan::AES_*)
  - libgcrypt (gcry_pk_encrypt, gcry_cipher_*, gcry_md_*)
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Crypto pattern registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CryptoPattern:
    regex: str
    algorithm: str
    library: str
    role: str  # key_exchange | signature | symmetric | hash | unknown
    severity: str  # error | warning | note
    rule_id: str
    key_size: int | None = None
    message: str = ""


PATTERNS: list[CryptoPattern] = [
    # ── OpenSSL RSA ──────────────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bRSA_generate_key(?:_ex)?\s*\(",
        algorithm="RSA",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS001",
        key_size=None,
        message="RSA key generation detected — quantum-vulnerable (Shor's algorithm).",
    ),
    CryptoPattern(
        regex=r"\bRSA_public_encrypt\s*\(",
        algorithm="RSA",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS002",
        message="RSA PKCS#1 v1.5 encryption — quantum-vulnerable; migrate to ML-KEM.",
    ),
    CryptoPattern(
        regex=r"\bRSA_private_decrypt\s*\(",
        algorithm="RSA",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS003",
        message="RSA PKCS#1 v1.5 decryption — quantum-vulnerable; migrate to ML-KEM.",
    ),
    CryptoPattern(
        regex=r"\bRSA_sign\s*\(",
        algorithm="RSA",
        library="OpenSSL",
        role="signature",
        severity="error",
        rule_id="CS004",
        message="RSA-SHA256 PKCS#1 v1.5 signing — quantum-vulnerable; migrate to ML-DSA.",
    ),
    CryptoPattern(
        regex=r"\bRSA_verify\s*\(",
        algorithm="RSA",
        library="OpenSSL",
        role="signature",
        severity="error",
        rule_id="CS005",
        message="RSA-SHA256 PKCS#1 v1.5 verification — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bEVP_PKEY_CTX_set_rsa_keygen_bits\s*\(",
        algorithm="RSA",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS006",
        message="RSA key generation via EVP — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bRSA_PKCS1_PADDING\b",
        algorithm="RSA",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS007",
        message="PKCS#1 v1.5 padding constant — implies Bleichenbacher-vulnerable RSA.",
    ),
    # ── OpenSSL ECDSA / EC ───────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bECDSA_do_sign\s*\(",
        algorithm="ECDSA",
        library="OpenSSL",
        role="signature",
        severity="error",
        rule_id="CS010",
        message="ECDSA P-256 signing — quantum-vulnerable (Shor's algorithm).",
    ),
    CryptoPattern(
        regex=r"\bECDSA_do_verify\s*\(",
        algorithm="ECDSA",
        library="OpenSSL",
        role="signature",
        severity="error",
        rule_id="CS011",
        message="ECDSA P-256 verification — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bECDH_compute_key\s*\(",
        algorithm="ECDH",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS012",
        message="ECDH key agreement — quantum-vulnerable; migrate to ML-KEM.",
    ),
    CryptoPattern(
        regex=r"\bEC_KEY_new_by_curve_name\s*\(",
        algorithm="ECDSA",
        library="OpenSSL",
        role="key_exchange",
        severity="warning",
        rule_id="CS013",
        message="EC key creation — verify the curve is not quantum-vulnerable.",
    ),
    # ── OpenSSL DH ───────────────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bDH_generate_parameters_ex\s*\(",
        algorithm="DH",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS020",
        message="Classic DH parameter generation — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bDH_compute_key\s*\(",
        algorithm="DH",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS021",
        message="Classic DH shared secret — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bDH_generate_key\s*\(",
        algorithm="DH",
        library="OpenSSL",
        role="key_exchange",
        severity="error",
        rule_id="CS022",
        message="DH key pair generation — quantum-vulnerable.",
    ),
    # ── OpenSSL AES-CBC ──────────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bAES_cbc_encrypt\s*\(",
        algorithm="AES-CBC",
        library="OpenSSL",
        role="symmetric",
        severity="warning",
        rule_id="CS030",
        message="AES-CBC low-level encrypt — not quantum-broken but unauthenticated; "
        "prefer AES-GCM or ChaCha20-Poly1305.",
    ),
    CryptoPattern(
        regex=r"\bAES_set_encrypt_key\s*\(",
        algorithm="AES",
        library="OpenSSL",
        role="symmetric",
        severity="note",
        rule_id="CS031",
        message="AES key schedule set — low-level deprecated API.",
    ),
    CryptoPattern(
        regex=r"\bSSL_CTX_set_cipher_list\s*\(",
        algorithm="TLS-cipher",
        library="OpenSSL",
        role="symmetric",
        severity="warning",
        rule_id="CS032",
        message="Legacy TLS cipher list — check for RSA key exchange suites.",
    ),
    # ── OpenSSL MD5 / SHA-1 ──────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bMD5_Init\s*\(|\bMD5_Update\s*\(|\bMD5_Final\s*\(|\bMD5\s*\(",
        algorithm="MD5",
        library="OpenSSL",
        role="hash",
        severity="error",
        rule_id="CS040",
        message="MD5 usage — collision-broken, do not use for security purposes.",
    ),
    CryptoPattern(
        regex=r"\bSHA1_Init\s*\(|\bSHA1_Update\s*\(|\bSHA1_Final\s*\(|\bSHA1\s*\(",
        algorithm="SHA-1",
        library="OpenSSL",
        role="hash",
        severity="error",
        rule_id="CS041",
        message="SHA-1 usage — deprecated for signatures (SHAttered collision attack).",
    ),
    CryptoPattern(
        regex=r"\bEVP_md5\s*\(\)",
        algorithm="MD5",
        library="OpenSSL",
        role="hash",
        severity="error",
        rule_id="CS042",
        message="EVP MD5 digest — collision-broken.",
    ),
    CryptoPattern(
        regex=r"\bEVP_sha1\s*\(\)",
        algorithm="SHA-1",
        library="OpenSSL",
        role="hash",
        severity="warning",
        rule_id="CS043",
        message="EVP SHA-1 digest — deprecated for signing; still acceptable in HMAC-SHA1.",
    ),
    CryptoPattern(
        regex=r"\bHMAC\s*\(\s*EVP_md5\s*\(\)",
        algorithm="HMAC-MD5",
        library="OpenSSL",
        role="hash",
        severity="error",
        rule_id="CS044",
        message="HMAC-MD5 — weak; replaced by HMAC-SHA256.",
    ),
    CryptoPattern(
        regex=r"\bHMAC\s*\(\s*EVP_sha1\s*\(\)",
        algorithm="HMAC-SHA1",
        library="OpenSSL",
        role="hash",
        severity="warning",
        rule_id="CS045",
        message="HMAC-SHA1 — deprecated; replace with HMAC-SHA256.",
    ),
    # ── mbedTLS ──────────────────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bmbedtls_rsa_gen_key\s*\(",
        algorithm="RSA",
        library="mbedTLS",
        role="key_exchange",
        severity="error",
        rule_id="CS050",
        message="mbedTLS RSA key generation — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bmbedtls_rsa_rsassa_pkcs1_v15_sign\s*\(",
        algorithm="RSA",
        library="mbedTLS",
        role="signature",
        severity="error",
        rule_id="CS051",
        message="mbedTLS RSA PKCS#1 v1.5 signing — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bmbedtls_ecdsa_sign\s*\(",
        algorithm="ECDSA",
        library="mbedTLS",
        role="signature",
        severity="error",
        rule_id="CS052",
        message="mbedTLS ECDSA signing — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bmbedtls_aes_setkey_enc\s*\(",
        algorithm="AES",
        library="mbedTLS",
        role="symmetric",
        severity="note",
        rule_id="CS053",
        message="mbedTLS AES key schedule — not quantum-broken but audit usage.",
    ),
    CryptoPattern(
        regex=r"\bmbedtls_ssl_conf_ciphersuites\s*\(",
        algorithm="TLS-cipher",
        library="mbedTLS",
        role="symmetric",
        severity="warning",
        rule_id="CS054",
        message="mbedTLS TLS cipher suite configuration — verify PQC suites are included.",
    ),
    # ── libgcrypt ────────────────────────────────────────────────────────────
    CryptoPattern(
        regex=r"\bgcry_pk_encrypt\s*\(",
        algorithm="RSA",
        library="libgcrypt",
        role="key_exchange",
        severity="error",
        rule_id="CS060",
        message="libgcrypt public key encrypt — likely RSA, quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bgcry_pk_sign\s*\(",
        algorithm="RSA/ECDSA",
        library="libgcrypt",
        role="signature",
        severity="error",
        rule_id="CS061",
        message="libgcrypt public key sign — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"\bgcry_md_open\s*\(",
        algorithm="unknown-hash",
        library="libgcrypt",
        role="hash",
        severity="note",
        rule_id="CS062",
        message="libgcrypt message digest open — audit the algorithm selected.",
    ),
    # ── Botan ────────────────────────────────────────────────────────────────
    CryptoPattern(
        regex=r"Botan::RSA_PrivateKey|Botan::RSA_PublicKey",
        algorithm="RSA",
        library="Botan",
        role="key_exchange",
        severity="error",
        rule_id="CS070",
        message="Botan RSA key — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"Botan::ECDSA_PrivateKey|Botan::ECDSA_PublicKey",
        algorithm="ECDSA",
        library="Botan",
        role="signature",
        severity="error",
        rule_id="CS071",
        message="Botan ECDSA key — quantum-vulnerable.",
    ),
    CryptoPattern(
        regex=r"Botan::ECDH_PrivateKey",
        algorithm="ECDH",
        library="Botan",
        role="key_exchange",
        severity="error",
        rule_id="CS072",
        message="Botan ECDH key — quantum-vulnerable.",
    ),
]

# Precompile regexes for performance
_COMPILED: list[tuple[re.Pattern[str], CryptoPattern]] = [
    (re.compile(p.regex), p) for p in PATTERNS
]

C_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


@dataclass
class CryptoFinding:
    file: str
    line: int
    col_start: int
    col_end: int
    rule_id: str
    algorithm: str
    library: str
    role: str
    severity: str
    key_size: int | None
    message: str
    matched_text: str


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


def scan_file(path: Path) -> list[CryptoFinding]:
    """Scan a single C/C++ source file and return all crypto findings."""
    findings: list[CryptoFinding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for lineno, line_text in enumerate(lines, start=1):
        # Skip preprocessor-only comment lines
        stripped = line_text.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        for compiled_re, pattern in _COMPILED:
            for match in compiled_re.finditer(line_text):
                findings.append(
                    CryptoFinding(
                        file=str(path),
                        line=lineno,
                        col_start=match.start() + 1,
                        col_end=match.end() + 1,
                        rule_id=pattern.rule_id,
                        algorithm=pattern.algorithm,
                        library=pattern.library,
                        role=pattern.role,
                        severity=pattern.severity,
                        key_size=pattern.key_size,
                        message=pattern.message,
                        matched_text=match.group(0),
                    )
                )

    return findings


def scan_directory(root: Path, extensions: set[str] = C_EXTENSIONS) -> list[CryptoFinding]:
    """Recursively scan all C/C++ files under *root*."""
    all_findings: list[CryptoFinding] = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix.lower() in extensions:
            all_findings.extend(scan_file(path))
    return all_findings
