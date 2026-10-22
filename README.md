# Richtofen PHP2Shell Detector

**Live PHP fingerprinting and CVE exposure assessment**

**Version 1.0** · **Author: 0xRichtofen** · **Python 3.9+**

</div>

---

Richtofen PHP2Shell Detector is a lightweight, standard-library Python scanner that collects PHP version evidence from live HTTP targets and evaluates potential exposure to **CVE-2026-109618** and **CVE-2026-109619**.

It is designed for authorized security assessments and bug bounty reconnaissance. **It does not exploit either CVE or confirm remote code execution.**

## Features

- Scan a single URL or a list of targets.
- Identify PHP versions from HTTP response headers.
- Optionally check common `phpinfo()` paths for additional version evidence.
- Track the **source** of version evidence separately from the **endpoint** that returned it.
- Distinguish potentially affected versions, upstream-fixed versions, and inconclusive findings.
- Check a locally installed PHP executable.
- Support custom HTTP headers, request delays, timeouts, and limited concurrency.
- Export results to JSON and CSV.
- Avoid cross-origin redirects and use non-destructive HTTP checks.

## Installation

```bash
git clone https://github.com/0xRichtofen/php2shell-detector.git
cd richtofen-php2shell-detector
python3 --version
```

Requires **Python 3.9+**. No third-party Python packages are required.

## Usage

Scan one target:

```bash
python3 php_audit.py https://example.com
```

Scan a list of authorized targets:

```bash
python3 php_audit.py -l targets.txt --phpinfo-paths -t 2 --delay 1 -o results
```

Supply a custom header:

```bash
python3 php_audit.py https://example.com -H 'X-Researcher: your-handle'
```

Check the local PHP executable:

```bash
python3 php_audit.py --local
```

Display all available options:

```bash
python3 php_audit.py --help
```

## Example output

```text
================================================
  RICHTOFEN PHP2SHELL DETECTOR
  v1.0 | Author: 0xRichtofen
================================================

[200] https://example.com/
      PHP:        8.3.35
      Source:     header:x-powered-by
      Endpoint:   https://example.com/
      Confidence: MEDIUM
      Status:     BELOW_UPSTREAM_FIX
      PHP2Shell:  POTENTIALLY_AFFECTED
      Exploit:    NOT_CONFIRMED
```

*Illustrative output only; not a finding against a real target.*

## Understanding results

| Field | Meaning |
| --- | --- |
| `PHP` | PHP version observed, if available |
| `Source` | Type of evidence, such as `header:x-powered-by` |
| `Endpoint` | URL whose response provided the evidence |
| `Confidence` | Confidence in the fingerprint, **not** in exploitability |
| `Status` | Version comparison or legacy-branch assessment |
| `PHP2Shell` | CVE exposure assessment based on available evidence |
| `Exploit` | `NOT_CONFIRMED`: no exploitation verification was performed |

### Assessment labels

- **`POTENTIALLY_AFFECTED`** — a legacy PHP branch or a version below the configured upstream fix threshold; not proof of vulnerability.
- **`UPSTREAM_FIXED`** — a detected version meets the configured upstream fixed-version threshold; does not establish the patch state of every deployment.
- **`INCONCLUSIVE`** — no reliable version or conflicting/insufficient evidence.
- **`NOT_CONFIRMED`** — the scanner has not demonstrated successful exploitation.

**Important:** HTTP banners may be inaccurate, outdated, or affected by proxies. Linux distributions may backport security patches without changing the apparent upstream version. A `500` response or an outdated version banner alone does not prove either CVE is exploitable.

## Output files

With `-o results`, the scanner writes:

```text
results.json
results.csv
```

These files contain scan results and supporting evidence for manual review.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Responsible use

Use only on systems you own or are explicitly authorized to assess. Respect each program's scope, traffic limits, and disclosure rules. This scanner performs live HTTP requests; `--phpinfo-paths` and additional paths generate extra requests. It does **not** run memory-exhaustion probes, intentionally crash PHP workers, or execute RCE payloads.


## Author

**0xRichtofen**
