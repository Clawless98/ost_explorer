# ost_explorer — PST/OST Triage Tool for Penetration Testing

## Overview

A Python CLI + TUI tool for opening, parsing, searching, and analyzing PST/OST email archive files during penetration test engagements. Designed for post-exfiltration analysis on the operator's local machine.

**Goals:**
- Parse PST, OST, and best-effort encrypted OST files
- Provide an interactive Outlook-like terminal interface for browsing mailboxes
- Automatically detect credentials, secrets, PII, and sensitive data
- Support configurable detection rules accessible to non-technical team members
- Export findings and data in JSON, CSV, and HTML report formats

---

## Architecture

Four-layer design:

```
┌─────────────────────────────────────┐
│           Textual TUI               │  Interactive email-client interface
├─────────────────────────────────────┤
│         Core Engine                 │  Search, detection, extraction logic
├─────────────────────────────────────┤
│        Mailbox Abstraction          │  Unified API over PST/OST formats
├─────────────────────────────────────┤
│     libpff (pypff) + olefile        │  Format parsers
└─────────────────────────────────────┘
```

---

## Layer 1: Mailbox Abstraction

### Data Models (dataclasses)

- **Mailbox** — top-level container: file path, format type (PST/OST), item counts, folder tree
- **Folder** — name, message count, child folders (recursive tree)
- **Message** — sender, recipients (to/cc/bcc), subject, datetime, body (plain + HTML), headers, attachments list, read/unread flag
- **Attachment** — filename, size, MIME type, lazy byte extraction (bytes loaded on demand, not upfront)
- **Contact** — display name, email addresses, phone numbers, organization, title

### Parser Interface

```python
class MailboxParser:
    def open(path: str) -> Mailbox
    def get_folders(mailbox) -> list[Folder]
    def get_messages(folder, offset, limit) -> list[Message]
    def get_attachment_bytes(attachment) -> bytes
    def get_recovered_messages() -> list[Message]
```

### Design Decisions

- **Lazy loading throughout** — folders load on expand, messages load in pages of 50, attachment bytes load on explicit extract. Handles multi-GB PST files without blowing memory.
- **pypff primary, olefile fallback** — try pypff first, fall back to olefile-based parsing for files pypff cannot handle (corrupted/partial files).
- **Encrypted OST handling** — pypff can open some profile-encrypted OST files. When it cannot, detect early and report what is accessible (folder structure, metadata) vs what is locked (message bodies).
- **Format auto-detection** — sniff file header bytes to determine PST vs OST rather than relying on file extension.
- **SQLite metadata cache** — after first parse, serialize folder tree and message metadata (not bodies/attachments) to a SQLite file alongside the PST. Second launch is instant. Invalidate by checking file modification time and size.
- **Deleted item recovery** — libpff can access unallocated data in PST files containing messages the user deleted and emptied from trash. Exposed via `get_recovered_messages()` and shown in a dedicated "Recovered" folder in the TUI.

---

## Layer 2: Core Engine

### 2.1 Search Engine

Full-text search across subject, body, sender, recipients with filter syntax:

| Filter | Example | Description |
|--------|---------|-------------|
| `from:` | `from:john@corp.com` | Sender filter |
| `to:` | `to:admin` | Recipient filter |
| `has:attachment` | `has:attachment` | Messages with attachments |
| `filename:` | `filename:*.xlsx` | Attachment filename glob |
| `date:` | `date:2025-01..2025-03` | Date range |
| `folder:` | `folder:Inbox` | Scope to folder |

Filters are combinable: `from:ceo has:attachment date:2025-01..2025-06`

Search results populate the message list pane and are browsable like a folder. Hits are highlighted in the message viewer.

### 2.2 Sensitive Data Scanner

#### Built-in Detection Rules

**Credentials & Secrets:**
- Passwords in common formats ("password:", "pwd=", "pass:", "credentials:", "login:")
- API keys: AWS (AKIA...), Azure, GCP, GitHub (ghp_/ghs_), GitLab, Slack, Stripe, Twilio, SendGrid, Mailgun, JWT tokens
- Private keys (PEM headers, PGP blocks, SSH keys)
- Connection strings (JDBC, ODBC, MongoDB, Redis, PostgreSQL, MySQL)
- OAuth tokens, bearer tokens, session IDs
- Basic auth in URLs (https://user:pass@host)
- KeePass/1Password/LastPass vault references

**Network & Infrastructure:**
- Internal IPs (RFC1918 ranges), hostnames, FQDNs
- UNC paths (\\server\share)
- VPN configurations, gateway addresses
- RDP/SSH connection details
- Firewall rules, ACLs mentioned in body text
- WiFi SSIDs and passwords
- DNS records, internal domain names

**PII & Compliance:**
- SSN (with Luhn validation to reduce false positives)
- Credit card numbers (Luhn validated, major card patterns)
- Bank account/routing numbers
- Passport numbers, driver's license patterns
- Phone numbers (domestic + international)
- Physical addresses (street pattern matching)
- Dates of birth near PII context

**Files & Attachments:**
- Private keys (.pem, .key, .ppk, .pfx)
- Password databases (.kdbx, .1pif)
- Config files (.conf, .cfg, .ini, .env, .yaml with secrets)
- Scripts (.ps1, .bat, .sh)
- Office docs with macros (.xlsm, .docm)
- Archives (.zip, .7z, .rar — flagged for manual review)
- Certificate files (.crt, .cer, .p12)
- Database dumps (.sql, .bak)

**Contextual Patterns:**
- "Do not share", "confidential", "internal only", "eyes only"
- "Temporary password", "reset link", "one-time code"
- "Attached is the", "see attached" near sensitive file types
- Reply chains containing credential exchanges (password-like strings within 2 lines of "here are the" / "as requested")

**Recursive attachment inspection** — archives (.zip, .7z) are extracted in-memory and scanned. Embedded .eml files (forwarded emails) are parsed and scanned recursively.

#### Custom Rule Files (YAML)

Three levels of rule complexity for mixed-skill teams:

```yaml
# Simple keyword — no regex needed, anyone can write these
- name: vpn credentials
  find: "vpn password"
  severity: high
  note: "Look for VPN access creds"

# Multiple keywords — matches any
- name: project codenames
  find_any:
    - "Project Nightfall"
    - "Operation Sunrise"
    - "codename atlas"
  severity: medium
  note: "Client M&A project names"

# Advanced regex for power users
- name: employee ids
  pattern: "EMP-\\d{6}"
  severity: low
```

- `find` — plain text, case-insensitive match
- `find_any` — list of plain text keywords, matches any
- `pattern` — full regex
- All share `severity` (low/medium/high/critical) and `note` fields
- Rule files validated on load with clear error messages: `"Rule 'vpn credentials' on line 3: missing 'find', 'find_any', or 'pattern' field"`

### 2.3 Export Engine

- **JSON** — full structured dump (messages, metadata, findings) for scripting
- **CSV** — flat tables: messages (metadata columns), contacts, scan findings
- **HTML report** — standalone single-file HTML via Jinja2 template with embedded CSS. Sections: executive summary (counts, date range, top findings), credential/sensitive data findings with context, contact list, folder statistics
- **Attachment extraction** — bulk extract to directory tree mirroring folder structure, or selective from TUI
- All exports support scope filtering: everything, single folder, or current search results

---

## Layer 3: Textual TUI

### Layout

Three-pane split with Outlook-like navigation:

```
┌─ Folders [F1] ─┬─ Messages [F2] ──────────────────────┐
│ Inbox (342)     │ * john@co.. Budget Q3..    Mar 15    │
│ Sent Items      │   jane@co.. RE: VPN cr..   Mar 14    │
│ Drafts          │   admin@c.. Password r..   Mar 12    │
│ Deleted         │   cfo@cor.. Wire trans..   Mar 10    │
│ Contacts        │                                       │
│ Calendar        │                                       │
│ Recovered       │                                       │
├─────────────────┴──────────────────────────────────────┤
│ From: jane@corp.com                                    │
│ To: user@corp.com                                      │
│ Subject: RE: VPN credentials                           │
│ Attachments: [vpn_config.ovpn] [notes.txt]             │
│─────────────────────────────────────────────────────────│
│ Hey, here are the creds you asked for:                 │
│ Username: jdoe  Password: ** Summer2025! **            │
│                                                        │
│ Let me know if you need anything else.                 │
└─────────────────────────────────────────────────────────┘
 /search  s:scan  e:export  a:save attachment  q:quit
```

### Behaviors

- **Folder tree** — expandable/collapsible, message counts, "Recovered" folder for deleted item recovery
- **Message list** — sortable by date/sender/subject, star/flag messages of interest, unread indicators, paginated with lazy loading on scroll
- **Message viewer** — headers on top, body below, plain text default with HTML toggle, interactive attachment list (enter to extract)
- **Scan findings highlighted** — detected credentials/secrets highlighted inline in message body with color by severity
- **Search bar** — `/` to open, supports full filter syntax, results replace message list

### Keybindings

| Key | Action |
|-----|--------|
| `F1` / `F2` / `F3` | Focus folder / message list / viewer pane |
| `/` | Open search bar |
| `s` | Run scanner on current scope |
| `e` | Export dialog (format, scope) |
| `a` | Extract selected attachment |
| `A` | Bulk extract all attachments from current scope |
| `f` | Flag/star message |
| `t` | Toggle HTML/plain text view |
| `n` / `p` | Next / previous message |
| `?` | Help overlay |
| `q` | Quit |

### Status Bar

Bottom bar shows: filename, format (PST/OST), total messages, scan status, current search query.

---

## Layer 4: CLI Interface

### Commands

```bash
# Interactive browsing
ost_explorer browse <file>

# Headless scan
ost_explorer scan <file>
ost_explorer scan <file> --rules custom_rules.yaml --output findings.json
ost_explorer scan <file> --severity high --format csv

# Bulk export
ost_explorer export <file> --format json --output dump.json
ost_explorer export <file> --format csv --output-dir ./export/
ost_explorer export <file> --format html --output report.html
ost_explorer export <file> --attachments --output-dir ./attachments/

# Utilities
ost_explorer info <file>           # Quick summary: format, folders, message count, date range
ost_explorer validate <rules.yaml> # Validate custom rule files
```

### Common Flags

| Flag | Description |
|------|-------------|
| `--rules` / `-r` | Path to custom rule YAML (repeatable) |
| `--output` / `-o` | Output file path |
| `--format` / `-f` | json, csv, html |
| `--severity` | Minimum severity filter (low/medium/high/critical) |
| `--folder` | Scope to specific folder |
| `--include-deleted` | Include recovered/deleted items (default on for scan) |
| `--quiet` / `-q` | Suppress banner and progress |
| `--no-cache` | Skip SQLite cache, parse fresh |

### Exit Codes

- `0` — success, no findings
- `1` — success, findings detected
- `2` — error

---

## Dependencies

- **pypff** (libpff Python bindings) — primary PST/OST parser
- **olefile** — fallback parser for corrupted/partial files
- **textual** — TUI framework
- **pyyaml** — custom rule file parsing
- **jinja2** — HTML report templating
- **click** — CLI framework

---

## Project Structure

```
ost_explorer/
├── src/
│   └── ost_explorer/
│       ├── __init__.py
│       ├── cli.py              # Click CLI entry point
│       ├── models.py           # Data classes (Mailbox, Folder, Message, etc.)
│       ├── parser/
│       │   ├── __init__.py
│       │   ├── base.py         # MailboxParser interface
│       │   ├── pypff_parser.py # pypff implementation
│       │   ├── ole_parser.py   # olefile fallback
│       │   └── cache.py        # SQLite metadata cache
│       ├── engine/
│       │   ├── __init__.py
│       │   ├── search.py       # Search engine with filter syntax
│       │   ├── scanner.py      # Sensitive data scanner
│       │   └── export.py       # JSON/CSV/HTML export
│       ├── rules/
│       │   ├── __init__.py
│       │   ├── loader.py       # YAML rule loader + validator
│       │   └── default_rules.yaml  # Built-in detection rules
│       ├── tui/
│       │   ├── __init__.py
│       │   ├── app.py          # Main Textual app
│       │   ├── folder_tree.py  # Folder pane widget
│       │   ├── message_list.py # Message list pane widget
│       │   ├── message_view.py # Message viewer pane widget
│       │   ├── search_bar.py   # Search input widget
│       │   └── export_dialog.py # Export options dialog
│       └── templates/
│           └── report.html     # Jinja2 HTML report template
├── rules/                      # Directory for custom rule files
│   └── example_rules.yaml
├── tests/
├── pyproject.toml
└── README.md
```
