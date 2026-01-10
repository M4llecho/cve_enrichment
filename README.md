# CVE Enrichment System

Sistema completo per arricchire CVE con dati da fonti esterne e salvarli in MariaDB.

## Funzionalità

- **Dati base da NVD**: descrizione, CVSS, CWE
- **Catena MITRE**: CWE → CAPEC → Tecniche ATT&CK → Tattiche
- **EPSS score**: probabilità di exploit
- **KEV**: verifica se la CVE è nella lista CISA Known Exploited Vulnerabilities

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

### Aggiornamento Completo (CVE + EPSS + KEV)

```bash
# Esegue in sequenza: update-cve, update-epss, update-kev
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
| `update-all` | Aggiornamento completo: CVE + EPSS + KEV |
| `enrich-cve <CVE-ID>` | Arricchisce una singola CVE |
| `enrich-list <file>` | Arricchisce CVE da file |
| `show <CVE-ID>` | Mostra dati di una CVE |
| `stats` | Mostra statistiche database |

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
    cvss_v3_score, cvss_v3_vector, cvss_severity,
    cwe_id, cwe_name,
    capec_ids, technique_ids, technique_names, tactic_ids, tactic_names,
    epss_score, epss_percentile,
    in_kev, kev_date_added, kev_due_date, kev_ransomware_use,
    last_enriched_at
)
```

## Fonti Dati

| Fonte | URL | Contenuto |
|-------|-----|-----------|
| NVD | https://services.nvd.nist.gov/rest/json/cves/2.0 | CVE, CWE, CVSS |
| CWE | https://cwe.mitre.org/data/xml/cwec_latest.xml.zip | CWE → CAPEC mapping |
| CAPEC | https://capec.mitre.org/data/xml/capec_latest.xml | CAPEC → ATT&CK mapping |
| ATT&CK | https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json | Technique → Tactic |
| EPSS | https://api.first.org/data/v1/epss | Exploit probability |
| KEV | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Known exploited |

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

--- CVSS ---
Score: 10.0 (CRITICAL)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

--- CWE ---
ID: CWE-502
Name: Deserialization of Untrusted Data

--- MITRE Chain ---
CAPEC IDs: CAPEC-586
Techniques: T1059, T1190, T1210
Tactics: Execution, Initial Access, Lateral Movement

--- EPSS ---
Score: 0.9756 (Percentile: 0.9990)

--- KEV ---
In KEV: Yes
Date Added: 2021-12-10
Due Date: 2021-12-24
Ransomware Use: Yes

Last Enriched: 2024-01-15 14:30:00
============================================================
```
