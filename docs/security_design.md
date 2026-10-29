# Security design

## Format and validation

The top-level JSON keys are exactly `metadata`, `encrypted_session_key`, `nonce`, `ciphertext`, `authentication_tag`, and `signature`. Metadata has exactly the seven documented string fields: protocol version (`1.0`), package UUID, UTC timestamp, original filename, and fixed identifiers `AES-256-GCM`, `RSA-OAEP-SHA256`, `RSA-PSS-SHA256`. Binary values use strict Base64. The nonce must be 12 bytes; tag 16 bytes; session key after OAEP unwrapping 32 bytes. Unknown versions, algorithms, types, fields, malformed JSON/Base64 and oversized packages are rejected.

Canonical encoding is UTF-8 JSON with recursively sorted keys, compact separators `(',', ':')`, and no ASCII escaping requirement (`ensure_ascii=False`). The signature covers this representation of every top-level field except `signature`. The GCM AAD is the same canonical encoding of the metadata object. AES-GCM covers the plaintext and AAD; its ciphertext and tag are then covered by the package signature.

## Controls

AES-256-GCM encrypts the paper and authenticates ciphertext plus metadata. A fresh CSPRNG-generated 256-bit session key is used per package. A fresh 96-bit nonce is generated for each encryption; nonce reuse with a given GCM key is dangerous, and fresh keys further reduce reuse risk. The session key is encrypted using the recipient RSA public key and OAEP-SHA256 with fixed label `secure-exam-exchange-v1`.

RSA-PSS-SHA256 signs the complete encrypted package representation. Successful verification means the package was signed by the holder of the private key corresponding to the trusted sender public key. It does not establish a human identity by itself: the key must be reliably bound to that person. Public-key fingerprints should be verified through an independent trusted channel. Encryption alone does not identify the sender.

The receiver validates, verifies signature, unwraps the key, authenticates/decrypts in memory, then writes to a temporary file and atomically links it to a sanitized, non-overwriting destination. Failed signature, OAEP, or GCM checks release no plaintext file. AAD and the signature serve related but distinct checks; GCM authentication remains required after signature verification to ensure authenticated encryption succeeds.

## Boundaries

Confidentiality restricts reading to the intended recipient; integrity detects unauthorized changes; authentication ties the signed package to possession of a trusted private key; authorization (whether a person may send/receive a particular exam) is not implemented. The system cannot protect a compromised endpoint, stolen passwords/keys, malicious trusted sender, traffic analysis, deletion, denial of service, or an incorrectly distributed trusted key. Timestamps and random package IDs do not prevent replay: production needs a recipient-side replay database and policy. Production deployment also needs key lifecycle/revocation, secure secret handling, backups, access control, audit, malware defenses, operational procedures, and reviewed protocols. This is an educational controlled demonstration, not a production examination service.
