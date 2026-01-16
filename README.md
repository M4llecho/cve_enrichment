# CVE Enrichment System

Sistema completo per arricchire CVE con dati da fonti esterne e salvarli in MariaDB.

## Funzionalità

- **Dati base da NVD**: descrizione, CVSS, CWE
- **Catena MITRE**: CWE → CAPEC → Tecniche ATT&CK → Tattiche
- **EPSS score**: probabilità di exploit
- **KEV**: verifica se la CVE è nella lista CISA Known Exploited Vulnerabilities
- **Sigma Detection Rules**: regole di detection da SigmaHQ associate alle CVE
- **Nuclei Templates**: exploit templates da ProjectDiscovery associati alle CVE
- **Snort/Suricata IDS Rules**: regole IDS/IPS da Emerging Threats Open associate alle CVE
- **LLM Kill Chain Tagging**: classificazione automatica delle CVE per ricostruzione killchain con LLM locale (Ollama)

## Requisiti

- Python 3.10+
- MariaDB

## Installazione

```bash
# Clona/copia il progetto
cd cve_enrichment

# Installa dipendenze
pip install -r requirements.txt

# Configura il database
cp .env.example .env
# Modifica .env con le tue credenziali DB
```

## Configurazione

Crea un file `.env` basato su `.env.example`:

```env
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=cve_enrichment

SSL_VERIFY=true

# Opzionale: aumenta il rate limit NVD da 5 a 50 req/30sec
NVD_API_KEY=your_api_key
```

## Uso

### Flag Globali

| Flag | Descrizione |
|------|-------------|
| `-v`, `--verbose` | Abilita logging DEBUG (più dettagliato) |
| `-f`, `--force` | Forza re-download dei file anche se in cache |

### Inizializzazione

```bash
# Crea schema DB e scarica tutte le tabelle di mapping
python main.py init
# oppure
python main.py --init

# Con force re-download
python main.py init -f
```

### Aggiornamento Mappings

```bash
# Aggiorna solo le tabelle di mapping (CWE→CAPEC, CAPEC→Technique, etc.)
python main.py update-mappings
# oppure
python main.py --update-mappings

# Forza re-download dei file anche se in cache
python main.py update-mappings -f
```

### Popolamento Database (Raccomandato)

```bash
# Bulk fetch di tutte le CVE da NVD Feeds (VELOCE - metodo raccomandato)
python main.py fetch
# oppure
python main.py --fetch

# Con batch size personalizzato (default: 500)
python main.py fetch --batch-size 1000

# Forza re-download dei feed
python main.py fetch -f
```

### Aggiornamento Incrementale CVE

```bash
# Aggiorna solo le CVE modificate di recente via NVD API
python main.py update-cve
# oppure
python main.py --update-cve

# Con batch size personalizzato (default: 100)
python main.py update-cve --batch-size 200
```

### Aggiornamento EPSS

```bash
# Aggiorna gli score EPSS per tutte le CVE nel database
python main.py update-epss
# oppure
python main.py --update-epss

# Con batch size personalizzato (default: 1000)
python main.py update-epss --batch-size 2000

# Forza re-download anche se in cache
python main.py update-epss -f
```

### Aggiornamento KEV

```bash
# Aggiorna lo stato KEV per tutte le CVE nel database
python main.py update-kev
# oppure
python main.py --update-kev

# Con batch size personalizzato (default: 1000)
python main.py update-kev --batch-size 2000

# Forza re-download anche se in cache
python main.py update-kev -f
```

### Aggiornamento Sigma Detection Rules

```bash
# Aggiorna le regole Sigma per tutte le CVE nel database
python main.py update-sigma
# oppure
python main.py --update-sigma

# Con batch size personalizzato (default: 1000)
python main.py update-sigma --batch-size 2000

# Forza re-download anche se in cache
python main.py update-sigma -f
```

### Aggiornamento Nuclei Templates

```bash
# Aggiorna i template Nuclei per tutte le CVE nel database
python main.py update-nuclei
# oppure
python main.py --update-nuclei

# Con batch size personalizzato (default: 1000)
python main.py update-nuclei --batch-size 2000

# Forza re-download anche se in cache
python main.py update-nuclei -f
```

### Aggiornamento Snort/Suricata IDS Rules

```bash
# Aggiorna le regole Snort/Suricata per tutte le CVE nel database
python main.py update-snort
# oppure
python main.py --update-snort

# Con batch size personalizzato (default: 1000)
python main.py update-snort --batch-size 2000

# Forza re-download anche se in cache
python main.py update-snort -f
```

### Aggiornamento Completo (CVE + EPSS + KEV + Sigma + Nuclei + Snort)

```bash
# Esegue in sequenza: update-cve, update-epss, update-kev, update-sigma, update-nuclei, update-snort
python main.py update-all
# oppure
python main.py --update-all

# Con batch size personalizzato per CVE (default: 100)
python main.py update-all --batch-size 200

# Forza re-download di tutti i dati
python main.py update-all -f
```

### Arricchimento Singole CVE

```bash
# Arricchisce una singola CVE
python main.py enrich-cve CVE-2021-44228
# oppure
python main.py --enrich-cve CVE-2021-44228

# Arricchisce da file (una CVE per riga)
python main.py enrich-list my_cves.txt
# oppure
python main.py --enrich-list my_cves.txt

# Con batch size personalizzato
python main.py enrich-list my_cves.txt --batch-size 50
```

### Visualizzazione

```bash
# Mostra dati arricchiti di una CVE
python main.py show CVE-2021-44228

# Mostra statistiche del database
python main.py stats
```

### Riepilogo Comandi

| Comando | Descrizione |
|---------|-------------|
| `init` | Inizializza DB e scarica mappings |
| `update-mappings` | Aggiorna solo le tabelle di mapping |
| `fetch` | Bulk download CVE da NVD Feeds (veloce) |
| `update-cve` | Aggiornamento incrementale CVE via NVD API |
| `update-epss` | Aggiorna score EPSS per tutte le CVE |
| `update-kev` | Aggiorna stato KEV per tutte le CVE |
| `update-sigma` | Aggiorna regole Sigma per tutte le CVE |
| `update-nuclei` | Aggiorna template Nuclei per tutte le CVE |
| `update-snort` | Aggiorna regole Snort/Suricata per tutte le CVE |
| `update-all` | Aggiornamento completo: CVE + EPSS + KEV + Sigma + Nuclei + Snort |
| `enrich-cve <CVE-ID>` | Arricchisce una singola CVE |
| `enrich-list <file>` | Arricchisce CVE da file |
| `show <CVE-ID>` | Mostra dati di una CVE |
| `stats` | Mostra statistiche database |
| `llm-tag` | Tag bulk di tutte le CVE non taggate con LLM |
| `llm-tag-cve <CVE-ID>` | Tag singola CVE con LLM |
| `llm-tag-list <file>` | Tag CVE da file con LLM |
| `llm-status` | Stato del tagger LLM |

## LLM Kill Chain Tagging

Il sistema supporta la classificazione automatica delle CVE per la ricostruzione di killchain usando un LLM locale tramite Ollama.

### Requisiti LLM

```bash
# Installa Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Avvia Ollama
ollama serve

# Scarica modello consigliato
ollama pull deepseek-r1:8b
```

### Configurazione LLM

Variabili d'ambiente opzionali:

```env
CVE_LLM_BACKEND=ollama          # Backend (default: ollama)
CVE_LLM_MODEL=deepseek-r1:8b    # Modello da usare
CVE_LLM_URL=http://localhost:11434  # URL Ollama
CVE_LLM_TIMEOUT=120             # Timeout in secondi
```

### Comandi LLM Tagging

```bash
# Verifica stato LLM
python main.py llm-status

# Tag singola CVE
python main.py llm-tag-cve CVE-2021-44228

# Tag CVE da file (una per riga)
python main.py llm-tag-list cve_list.txt

# Tag bulk di tutte le CVE non taggate
python main.py llm-tag --limit 100

# Re-tag tutte le CVE (anche quelle già taggate)
python main.py llm-tag --retag-all --limit 50
```

### Tassonomia Tag

Il sistema assegna tag in 3 categorie per ogni CVE:

**Kill Chain Phases** (12 tag) - Fasi ATT&CK:
- `initial_access`, `execution`, `persistence`, `privilege_escalation`
- `defense_evasion`, `credential_access`, `discovery`, `lateral_movement`
- `collection`, `exfiltration`, `command_and_control`, `impact`

**Prerequisites** (6 tag) - Input per chaining:
- `requires_network`, `requires_local`, `requires_auth`
- `requires_user_interaction`, `requires_privilege`, `requires_physical`

**Capabilities** (8 tag) - Output per chaining:
- `grants_code_execution`, `grants_admin_access`, `grants_user_access`
- `grants_credential_access`, `grants_network_pivot`, `grants_persistence`
- `grants_data_access`, `grants_dos`

### Ricostruzione Kill Chain

I tag permettono di ricostruire killchain collegando CVE:
- **CVE-A → CVE-B** se `capabilities(A)` soddisfa `prerequisites(B)`

Esempio:
```
Log4Shell (initial_access)     PrintNightmare (priv_escalation)
  Output: grants_admin_access  →  Input: requires_network ✓
```

## Schema Database

### Tabelle di Mapping

```sql
-- CWE → CAPEC
map_cwe_capec (cwe_id, capec_id)

-- CAPEC → ATT&CK Technique
map_capec_technique (capec_id, technique_id, technique_name)

-- Technique → Tactic
map_technique_tactic (technique_id, tactic_id, tactic_name)

-- Dettagli CWE
cwe_details (cwe_id, cwe_name, description)
```

### Tabella Principale

```sql
cve_enriched (
    cve_id,
    description, published_date, last_modified,
    cvss_score, cvss_vector, cvss_severity, cvss_version,
    vuln_status,
    cwe_ids, cwe_names,
    capec_ids, technique_ids, technique_names, tactic_ids, tactic_names,
    epss_score, epss_percentile,
    in_kev, kev_date_added, kev_due_date, kev_ransomware_use,
    has_exploit, exploit_count, has_patch, reference_count,
    affected_vendors, affected_products, affected_products_detail,
    has_detection_rules, detection_rules_count, detection_rules,
    has_nuclei_template, nuclei_template_count, nuclei_templates,
    has_snort_rules, snort_rules_count, snort_rules,
    llm_tags_version, llm_model_used, llm_tagged_at,
    kill_chain_phases, prerequisites, capabilities,
    last_enriched_at
)
```

#### Campi Affected Products

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `affected_vendors` | JSON | Lista vendor unici: `["apache", "microsoft"]` |
| `affected_products` | JSON | Lista prodotti unici: `["log4j", "windows"]` |
| `affected_products_detail` | JSON | Dettaglio vendor/product/tipo: `[{"vendor": "apache", "product": "log4j", "part": "a"}]` |

#### Campi Detection Rules (Sigma)

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `has_detection_rules` | BOOLEAN | True se esistono regole Sigma per questa CVE |
| `detection_rules_count` | INT | Numero di regole Sigma associate |
| `detection_rules` | JSON | Array di regole: `[{"id", "title", "level", "filename"}]` |

#### Campi Exploit Templates (Nuclei)

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `has_nuclei_template` | BOOLEAN | True se esistono template Nuclei per questa CVE |
| `nuclei_template_count` | INT | Numero di template Nuclei associati |
| `nuclei_templates` | JSON | Array di template: `[{"id", "name", "severity", "filename", "verified", "vendor", "product"}]` |

#### Campi IDS/IPS Rules (Snort/Suricata)

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `has_snort_rules` | BOOLEAN | True se esistono regole Snort/Suricata per questa CVE |
| `snort_rules_count` | INT | Numero di regole IDS associate |
| `snort_rules` | JSON | Array di regole: `[{"sid", "msg", "classtype", "severity", "filename"}]` |

#### Campi LLM Kill Chain Tagging

| Campo | Tipo | Descrizione |
|-------|------|-------------|
| `llm_tags_version` | VARCHAR(20) | Versione della tassonomia usata (es. "1.0.0") |
| `llm_model_used` | VARCHAR(100) | Modello LLM usato per il tagging |
| `llm_tagged_at` | DATETIME | Timestamp del tagging LLM |
| `kill_chain_phases` | JSON | Array fasi kill chain: `["initial_access", "execution"]` |
| `prerequisites` | JSON | Array prerequisiti: `["requires_network"]` |
| `capabilities` | JSON | Array capabilities: `["grants_admin_access", "grants_code_execution"]` |

## Fonti Dati

| Fonte | URL | Contenuto |
|-------|-----|-----------|
| NVD | https://services.nvd.nist.gov/rest/json/cves/2.0 | CVE, CWE, CVSS |
| CWE | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip | CWE → CAPEC mapping |
| CAPEC | https://capec.mitre.org/data/xml/capec_latest.xml | CAPEC → ATT&CK mapping |
| ATT&CK | https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json | Technique → Tactic |
| EPSS | https://api.first.org/data/v1/epss | Exploit probability |
| KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known exploited |
| SigmaHQ | https://github.com/SigmaHQ/sigma | Detection rules |
| Nuclei | https://github.com/projectdiscovery/nuclei-templates | Exploit templates |
| ET Open | https://rules.emergingthreats.net/open/ | IDS/IPS rules (Snort/Suricata) |

## Note

- **Rate Limiting NVD**: 5 req/30sec senza API key, 50 req/30sec con API key
- **Cache**: I file scaricati sono salvati in `cache/` con scadenza 24h
- **Logging**: Log dettagliati in `cve_enrichment.log`

## Esempio Output

```
============================================================
CVE ID: CVE-2021-44228
============================================================

Description: Apache Log4j2 2.0-beta9 through 2.15.0 (excludin...

Published: 2021-12-10 10:15:00+00:00
Last Modified: 2023-04-03 20:15:00+00:00
Status: Analyzed

--- CVSS ---
Version: 3.1
Score: 10.0 (CRITICAL)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

--- CWE ---
  CWE-20: Improper Input Validation
  CWE-400: Uncontrolled Resource Consumption
  CWE-502: Deserialization of Untrusted Data
  CWE-917: Improper Neutralization of Special Elements...

--- MITRE Chain ---
CAPEC IDs: CAPEC-586
Techniques: T1059, T1190, T1210
Tactics: Execution, Initial Access, Lateral Movement

--- EPSS ---
Score: 0.9756 (Percentile: 0.9990)

--- Exploit/Patch ---
Has Exploit: Yes (15 references)
Has Patch: Yes

--- Affected Products ---
Vendors: apache
Products: log4j

  - [app] apache / log4j

--- KEV ---
In KEV: Yes
Date Added: 2021-12-10
Due Date: 2021-12-24
Ransomware Use: Yes

--- Detection Rules (Sigma) ---
Has Rules: Yes (12 rules)
  - [high] Log4j RCE CVE-2021-44228 Generic
  - [high] Log4j RCE CVE-2021-44228 in Fields
  - [medium] Log4j Exploitation Indicators
  ... and 9 more

--- Exploit Templates (Nuclei) ---
Has Templates: Yes (5 templates)
  - [critical] Apache Log4j2 RCE (verified)
  - [critical] Log4j JNDI Injection (verified)
  - [high] Log4j Scanner Detection
  ... and 2 more

--- IDS/IPS Rules (Snort/Suricata) ---
Has Rules: Yes (3 rules)
  - [high] SID:2033647 ET EXPLOIT Apache Log4j RCE Attempt
  - [high] SID:2033648 ET EXPLOIT Log4j JNDI Injection
  - [medium] SID:2033649 ET SCAN Log4j Scanner Detection

References: 25
Last Enriched: 2024-01-15 14:30:00

--- LLM Kill Chain Tags ---
Model: deepseek-r1:8b
Taxonomy: 1.0.0
Tagged At: 2024-01-15 15:00:00
Kill Chain Phases: initial_access, execution
Prerequisites: requires_network
Capabilities: grants_admin_access, grants_code_execution
============================================================
```
