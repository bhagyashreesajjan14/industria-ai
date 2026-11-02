# INDUSTRIA AI — Intelligent Industrial Manual & Maintenance Assistant

An evidence-grounded, production-minded industrial knowledge application built with Django REST Framework, persistent ChromaDB vector storage, PyMuPDF extraction, and official Groq API LLM integration.

---

## 1. System Architecture

```
                       [ Engineer / Supervisor / Admin ]
                                      |
                     [ Bootstrap 5 Industrial UI ]
                                      |
                         [ Django REST Backend ]
                       /           |           \
         [ User Auth & RBAC ]  [ Machines API ]  [ Assistant RAG API ]
                                                       |
                                            [ VectorStoreService ]
                                            (ChromaDB Persistent)
                                           / strict machine_id \\
                                          /      filter         \\
                     [ M-HP200 Collection ]               [ M-AC90 Collection ]
                     - HP-OPS-01 (Rev 1.0)                 - AC-OM-01 (Rev 1.0)
                     - HP-MNT-01 (Rev 1.0)                         |
                              \                                    /
                               \                                  /
                                [ Retrieved Manual Evidence ]
                                              |
                                   [ Official Groq API ]
                               (llama-3.3-70b-versatile)
                               (Offline Synthesizer Fallback)
                                              |
                                 [ Grounded Answer JSON ]
                                 - Direct Answer
                                 - 1-Based Page Citations
                                 - Verifiable Passages
```

---

## 2. Machine & Manual Registration Inventory

The dataset consists of **2 distinct industrial machines** and **3 technical manuals** registered via `machine_manual_index.csv`:

| Machine Identifier | Model | Machine Name | Document ID | Revision | Pages | Chunks |
|---|---|---|---|---|---|---|
| **M-HP200** | HP-200 | Hydraulic forming press | **HP-OPS-01** | 1.0 | 3 | 17 |
| **M-HP200** | HP-200 | Hydraulic forming press | **HP-MNT-01** | 1.0 | 3 | 16 |
| **M-AC90** | AC-90 | Air compressor | **AC-OM-01** | 1.0 | 3 | 15 |

*Note: Both HP-200 operations and maintenance manuals belong to the single `M-HP200` machine record. When querying HP-200, evidence is retrieved from both manuals.*

---

## 3. Groq API Setup & Environment Configuration

### Exact `.env` File Location:
```
c:\Users\Bhagyashree\INDUSTRIA AI\.env
```

### Setup Instructions:
1. Open `.env` in your text editor (or copy from `.env.example`):
   ```bash
   copy .env.example .env
   ```
2. Insert your official Groq API key:
   ```ini
   GROQ_API_KEY=gsk_your_actual_groq_api_key_here
   GROQ_MODEL=llama-3.3-70b-versatile
   ```
3. Get a free Groq API key from: [https://console.groq.com/keys](https://console.groq.com/keys)

> **Resilience Guarantee:** If `GROQ_API_KEY` is not provided, the application runs seamlessly using the built-in **Deterministic Grounded Synthesizer**, allowing 100% offline development, testing, and evaluation.

---

## 4. Strong Authentication & Dedicated Role Portals (Direct Login)

INDUSTRIA AI implements an enterprise-grade authentication architecture meeting strict industrial security standards with seamless direct login:

### Dedicated Login Portals
- **Central Portal Gateway:** `/login/`
- **Operations & Maintenance Engineer Portal:** `/login/engineer/`
- **System Administrator Portal:** `/login/admin/`
- **Compliance & Audit Supervisor Portal:** `/login/supervisor/`

> **Strict Server-Side Role Enforcement:** Logging in with valid credentials at the wrong portal (e.g. an Engineer attempting to authenticate at `/login/admin/`) is immediately rejected with HTTP 403 `PORTAL_ROLE_MISMATCH` and logged to `SecurityAuditLog`.

### Security Hardening Features
1. **Direct Role Dashboard Redirection:**
   - On successful username and password verification, users are authenticated immediately without OTP/MFA barriers and redirected directly to their designated dashboard:
     - Admin -> `/admin-dashboard/`
     - Engineer -> `/engineer/`
     - Supervisor -> `/supervisor/`
2. **Brute-Force & Enumeration Protection:**
   - 15-minute temporary lockout after 5 consecutive failed attempts.
   - Uniform generic error messages (`Invalid username or password.`) to prevent username enumeration.
3. **Session Hardening & Security Middleware (`SecurityEnforcementMiddleware`):**
   - Active account lockout enforcement (terminates sessions for locked accounts).
   - 8-hour session lifetime (`SESSION_COOKIE_AGE = 28800`).
   - Session expires automatically on browser close (`SESSION_EXPIRE_AT_BROWSER_CLOSE = True`).
   - `HttpOnly` and `SameSite=Lax` cookies prevent XSS theft and CSRF abuse.
   - Session key rotation on authentication (`cycle_key()`) prevents session fixation attacks.
4. **Zero-Secret Security Audit Logging (`SecurityAuditLog`):**
   - Tracks security events (login success/failure, lockout, role mismatch, logouts).
   - Sanitizes and purges all passwords and sensitive information before database persistence.

### Pre-configured Security Accounts
Run `python backend/manage.py setup_security_users` to initialize accounts with strong passwords:

| Portal | Username | Strong Password | Role | Direct Dashboard |
|---|---|---|---|---|
| `/login/admin/` | `admin` | `Admin@Sec2026!` | **Administrator** | `/admin-dashboard/` |
| `/login/engineer/` | `engineer` | `Engineer@Sec2026!` | **Engineer** | `/engineer/` |
| `/login/supervisor/` | `supervisor` | `Supervisor@Sec2026!` | **Supervisor** | `/supervisor/` |

---

## 5. Execution & Ingestion Commands

Run all commands using the project's virtual environment:

### Step 1: Database Migrations
```powershell
& ".\venv\Scripts\python.exe" backend/manage.py migrate
```

### Step 2: Seed Users and Initial Data
```powershell
& ".\venv\Scripts\python.exe" backend/manage.py seed_industria
```

### Step 3: Initialize Strong Security Accounts
```powershell
& ".\venv\Scripts\python.exe" backend/manage.py setup_security_users
```

### Step 4: Run PDF Manual Ingestion
```powershell
& ".\venv\Scripts\python.exe" backend/manage.py ingest_manuals
```

### Step 5: Run Automated Test Suites (All 34 Tests)
```powershell
# Run both Domain RAG Tests and Strong Security Authentication Tests
& ".\venv\Scripts\python.exe" backend/manage.py test tests.test_industria tests.test_security_auth --verbosity=2
```

### Step 6: Start the Web Application
```powershell
& ".\venv\Scripts\python.exe" backend/manage.py runserver 0.0.0.0:8000
```
Open your browser at: `http://localhost:8000/`

---

## 6. Key Demonstration Scenarios

1. **HP-200 Alarm E17:**
   - Select: `HP-200`
   - Question: *"What does E17 mean?"*
   - Grounded Answer: Low hydraulic pressure. Place on HOLD; request checks in HP-MNT-01 page 3.
   - Citation: `HP-OPS-01` Page 2.

2. **AC-90 Alarm E17 (Machine Isolation):**
   - Select: `AC-90`
   - Question: *"What does E17 mean?"*
   - Grounded Answer: High discharge temperature. Record temperature; above 95°C request cooling-path review.
   - Citation: `AC-OM-01` Page 2.
   - *Strict isolation: Never returns HP-200 low hydraulic pressure.*

3. **Multi-Manual Integration (HP-200 Trigger + Observations):**
   - Select: `HP-200`
   - Question: *"What triggers E17, and what observations should be collected?"*
   - Grounded Answer: Triggers when pressure stays below 110 bar for >5s (normal: 120–140 bar). Observations to collect: reservoir level, external leakage, RF-20 restriction indicator, oil temperature/pressure.
   - Citations: `HP-OPS-01` Page 2 AND `HP-MNT-01` Page 3.

4. **Inspection Interval (AC-90 AF-10 Filter):**
   - Select: `AC-90`
   - Question: *"How often should the AF-10 filter indicator be checked, and when is planned replacement due?"*
   - Grounded Answer: Check indicator every 100 operating hours; planned replacement due every 600 operating hours.
   - Citation: `AC-OM-01` Page 3.

5. **Missing Evidence Boundary Guard:**
   - Select: `HP-200`
   - Question: *"What is the pump replacement price?"*
   - Grounded Status: `insufficient_evidence`.
   - Answer: *"The available manuals do not contain enough information to answer this question."*

6. **Cross-Machine Leakage Prevention:**
   - Select: `AC-90`
   - Question: *"What is the HP-200 return-filter replacement interval?"*
   - Grounded Status: `insufficient_evidence` (AC-90 manual does not contain HP-200 component data).

