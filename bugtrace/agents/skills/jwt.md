# Skill: JWT Analysis & Exploitation

This skill provides the knowledge base for analyzing, manipulating, and exploiting JSON Web Tokens (JWT).

## 1. Anatomy of a JWT

A JWT consists of three parts separated by dots (`.`):

- **Header**: Contains metadata about the token (e.g., algorithm `alg`, type `typ`, key ID `kid`).
- **Payload**: Contains claims (e.g., `sub`, `name`, `admin`, `iat`, `exp`).
- **Signature**: Ensures the token has not been tampered with.

## 2. Common Vulnerabilities

### 2.1 algorithm: "none"

The `none` algorithm allows a token to be verified without a signature.

- **Attack**: Change the `alg` in the header to `none` (or variations like `None`, `nOnE`) and remove the signature part (keep the trailing dot).

### 2.2 Weak HMAC Secrets

Tokens signed with HS256 use a symmetric secret. If the secret is weak (e.g., "secret", "password"), it can be brute-forced offline.

- **Attack**: Brute-force the secret using a wordlist and then forge tokens with arbitrary claims.

### 2.3 Algorithm Confusion (RS256 to HS256)

If the server supports both RS256 (asymmetric) and HS256 (symmetric), an attacker can use the server's public key (often publicly available) as the HMAC secret.

- **Attack**: Sign the token using the public key with the HS256 algorithm.

### 2.4 KID Manipulation

The `kid` (Key ID) header tells the server which key to use for verification.

- **Directory Traversal**: Change `kid` to point to a file on the server (e.g., `../../dev/null`) whose content you know or can control.
- **SQL Injection**: If the server looks up the `kid` in a database, inject SQL into the `kid` field.

### 2.5 JKU/JWK Header Injection

- **JKU (JWK Set URL)**: The server fetches the public key from this URL.
- **JWK (JSON Web Key)**: The public key is embedded directly in the header.
- **Attack**: Host your own JWKS file or embed your own JWK and point the server to it.

## 3. Methodology

1. **Detection**: Identify JWTs in `Authorization` headers, cookies, or web storage.
2. **Analysis**: Decode the token (Base64) without verification to inspect claims and headers.
3. **Passive Check**: Check for sensitive information (PII) in the payload and weak algorithms.
4. **Offline Brute Force**: Try common secrets if HS256 is used.
5. **Active Manipulation**:
   - Try `alg: none`.
   - Try Algorithm Confusion.
   - Try `kid` / `jku` injection.
   - Attempt Privilege Escalation by modifying roles or IDs in the payload.
6. **Verification**: Send the forged token back to the target and analyze the response (200 OK vs 401/403).
