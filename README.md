# ost_explorer

PST/OST email archive triage tool for penetration testing. Browse mailboxes in an Outlook-like terminal interface, automatically detect credentials and secrets, and export findings for reports.

## Install

```bash
# Install libpff (required for full PST/OST parsing)
sudo apt install libpff-dev

# Install ost_explorer
pip install -e ".[dev]"
```

## Usage

### Interactive browsing
```bash
ost_explorer browse mailbox.pst
```

### Scan for secrets
```bash
ost_explorer scan mailbox.pst
ost_explorer scan mailbox.pst --rules custom_rules.yaml --severity high
ost_explorer scan mailbox.pst --output findings.json --format json
```

### Export data
```bash
ost_explorer export mailbox.pst --format html --output report.html
ost_explorer export mailbox.pst --format json --output dump.json
ost_explorer export mailbox.pst --format csv --output data.csv
ost_explorer export mailbox.pst --attachments --output-dir ./attachments/
```

### File info
```bash
ost_explorer info mailbox.pst
```

### Validate custom rules
```bash
ost_explorer validate my_rules.yaml
```

## Custom Rules

Create YAML files with simple keyword or regex patterns:

```yaml
# Simple keyword — anyone can write these
- name: project codename
  find: "Project Nightfall"
  severity: high
  note: "Client M&A codename"

# Multiple keywords
- name: internal tools
  find_any:
    - "admin portal"
    - "staging server"
  severity: medium

# Regex for advanced patterns
- name: employee id
  pattern: "EMP-\\d{6}"
  severity: low
```

## TUI Keybindings

| Key | Action |
|-----|--------|
| `/` | Search |
| `s` | Scan current folder |
| `e` | Export dialog |
| `a` | Save attachment |
| `A` | Save all attachments |
| `f` | Flag message |
| `t` | Toggle HTML/plain text |
| `n/p` | Next/previous message |
| `F1/F2/F3` | Focus folders/messages/viewer |
| `?` | Help |
| `q` | Quit |
