# Splunk Diag wrapper for SOC Prime LogTotal (prototype 0.8)

This is not a fork or a replacement sanitization engine. Python handles tar archives and optional Ansible discovery; all sensitive-value transformations are delegated to the locally installed SOC Prime CLI. No Python packages are needed. Node.js 20+ and Python 3.10+ are required. Ansible is optional.

## Install

Run the installer from the project directory (Python 3.10+, Node.js 20+ and npm must already be installed):

```sh
./install.sh
# Or pin an approved upstream version:
./install.sh --version VERSION
```

The installer checks prerequisites, installs SOC Prime locally in `node_modules`, checks the CLI, and creates `anonymization.key` with permissions 0600. It prompts before proceeding if the key exists, preserves it by default, and requires typing `ROTATE` before replacing it. Back up an old key securely before rotation if previous support cases require correlation. `--key-file PATH` selects a different key. Relative paths are relative to the project directory. The installer requires npm registry access or an approved configured mirror; it does not install OS runtimes or Ansible. For repeatable dependency installation retain the generated package-lock.json and use `npm ci` in an approved environment.

Generate the key once per support case, never per file or archive. Do not share it. Run locally on a trusted encrypted volume; the wrapper creates private temporary files containing raw content and upstream reports. Cleanup is best effort, not secure erasure. Do not use the hosted LogTotal service for this workflow.

```sh
python3 sanitize_diag.py diag.tar.gz sanitized.tar.gz --cli ./node_modules/.bin/logtotal-sanitize --key-file anonymization.key --config config.json
python3 sanitize_diag.py diag2.tar.gz sanitized2.tar.gz --cli ./node_modules/.bin/logtotal-sanitize --key-file anonymization.key --config config.json -i inventory.yml
```

Use the same key, exact resolved inventory, config, CLI release and rules across a support case. `--inventory-json` accepts resolved `ansible-inventory --list` output instead; treat it as sensitive, since hostvars may contain credentials. `--vault-id` can be repeated with `-i`. Dynamic inventory plugins may use the network. `--cli` can point to an approved local executable. No npm or network calls are made by the wrapper itself.

## Policy

Default selected rules focus on infrastructure and credentials. All upstream rule IDs may be selected in config.json; for example add `paymentInfo`, `govIds`, `healthInfo`, `phoneNumbers`, `geoLocation` for broader PII detection after testing. Aggressive matching is off by default. `sensitive_terms` and inventory host identifiers are passed as additional literals via `--redact-file`; IPs use the native rule. Inventory aliases are separate strings, not canonicalized. Case variants are limited to exact/lower/upper forms. Literal substring matching and rule precedence are upstream behavior. A known hostname may receive a CUSTOM token while an unknown hostname receives a HOST token. The same value and rule/key produces the same token; changing detection context can change the rule ID and therefore the token.

`domains` contains literal DNS suffixes, not wildcards. Optional `inventory_discover_domains` discovers suffixes and explicit domain variables and removes redundant automatically discovered children. Exclusions affect discovery only. The optional generated JSON custom rule uses upstream regex fragments; its loading and interaction with built-in/alwaysRedact rules must be validated against the selected release. Explicit hostname literals may take precedence over domain rules. No DNS topology or IP syntax preservation is promised. Archive path tokens are normalized into filesystem-safe names; path and content tokens may differ in punctuation.

Archive filtering excludes known sensitive files, certificate/key formats, nested archives (including rotated .gz), selected database/search directories, nonregular entries, non-UTF-8/control-character files and oversized members. Limits default to 64 MiB per file, 4096 MiB total eligible text, 50000 members, and 180 seconds per CLI call. The wrapper reads each eligible member into memory; it is not end-to-end streaming. One upstream CLI process is launched per file and unique path component. Original archive stays unchanged. Output and report must not already exist. Raw tar metadata is not copied except modification time. Output report contains aggregate counts only; upstream reports are temporary and never included in the archive.

## Tests and release gate

`python3 -m unittest discover -s tests -v`

Ten local tests passed, including archive and batch processing with a mocked CLI. Real package installation was unavailable (npm DNS/network failure); the CLI contract, especially --redact-file and --rules-file, has not been validated end to end. Before any real diagnostics are released, test with synthetic tar archives and the exact approved upstream release. Confirm no original IPs, aliases, domains, secrets or path identifiers remain; compare identical values across separate bundles; check versions/timestamps and useful file paths; verify failure does not produce an archive; review exclusions and inspect the entire sanitized result. Built-in regexes and exclusions are not exhaustive. XML/config structure can be altered by tokens; no guarantee of Splunk diag parser compatibility or irreversible anonymization. No independent residual scanner in this prototype. Zero reported matches is not assurance of safety.

Upstream: https://github.com/socprime/logtotal-sanitizer

## Console progress (v0.4)

Interactive terminals display a single continuously rewritten progress line, with a bar, percentage, completed/total entries, sanitized and excluded counts, and current stage. Since v0.5 the total counts eligible regular files after extension and policy filtering; a candidate is complete when written or excluded for size or encoding. A preliminary streaming metadata pass counts entries, requiring a second decompression pass for compressed archives. No file contents are retained during counting. Heartbeats default to one second; redirected stderr uses plain text lines instead. A heartbeat confirms the wrapper is alive, not that the child process is making progress. The existing per-call timeout remains in effect.

```bash
python3 sanitize_diag.py original.tar.gz sanitized.tar.gz \
  --cli ./node_modules/.bin/logtotal-sanitize \
  --key-file anonymization.key --config config.json \
  --progress-interval 5
```

Use `--quiet` to suppress progress (the final success message and errors remain). Raw filenames, sensitive values, and upstream stdout/stderr are not printed. No key regeneration or reinstall is needed when upgrading an existing installation: replace `sanitize_diag.py` and keep the existing key, configuration and installed CLI. Do not overwrite local configuration with the template.

The wrapper still starts a separate upstream process per eligible file and uncached path component; progress reporting does not optimize this. Real upstream integration is still pending; tests use a mock CLI.

## File scope (v0.5)

By default only regular `.log`, `.conf`, and uncompressed numbered `.log.N` files are sanitized and included. All other files are omitted, not copied through. Existing sensitive-file and directory exclusions take priority. Compressed rotations (`.log.gz`) remain excluded. Matching is case-insensitive. Configure `"include_extensions": [".log", ".conf", ".txt"]` to expand scope explicitly. Existing configurations without this setting inherit the new default. The report includes `excluded_extension` and `target_files`; the live denominator counts eligible file types after policy exclusions, and includes candidates subsequently skipped for size or encoding. Skip counts include all exclusions. A complete candidate count does not mean archive publication has finished. This narrower archive may omit troubleshooting information such as system command outputs, CSV/JSON files and manifests; review with Support before release. No unsupported files are copied unchanged.

## Index name discovery (v0.7)

Pass `--indexes-conf PATH` once or multiple times to import index names from local Splunk configuration files. Only stanza names are read, not settings or values. Use a plain merged export (without `--debug`) from an indexer to cover all installed apps:

```sh
umask 077
/opt/splunk/bin/splunk btool indexes list > indexes.conf
```

Transfer the export securely to the sanitization workstation.

```sh
python3 sanitize_diag.py diag.tar.gz sanitized.tar.gz --cli ./node_modules/.bin/logtotal-sanitize --key-file anonymization.key --config config.json --indexes-conf indexes.conf
```

`[security_network]` and `[windows_events]` are imported; `[default]`, `[volume:hot]`, provider stanzas, internal names beginning with `_`, and invalid custom index names are ignored. Built-in non-internal indexes `main`, `summary`, and `history` are always excluded from index discovery. Duplicate names are removed. A file containing only excluded or default stanzas is valid and contributes no terms. Files without recognized stanza headers are rejected. Names are passed to the existing SOC Prime `--redact-file` dictionary, not a new encryption engine. Matching boundaries, rule precedence and replacements depend on SOC Prime; ordinary words used as index names (e.g. `main`) may cause false positives. Add additional exact index names to `index_exclusions` in config.json, for example `"index_exclusions": ["network", "windows"]`. These are additive to the built-in exclusions. This only controls index imports; manually registered terms, inventory terms and native SOC Prime rules remain independent. The same index list should be used for every diag in a case. The report includes counts only (`index_terms`, `sensitive_terms_total`); the input file is not added to the archive. The report's existing `inventory_terms` counter retains its prior meaning (manual and inventory terms before index import). Real SOC Prime integration is not verified here.

## Native batch processing (v0.8)

Batch mode processes separate archives sequentially in a single wrapper invocation. The key, configuration, inventory and index terms are loaded once and reused, along with the sanitized path-component cache. The original single-archive syntax remains supported. Limits apply per archive; the CLI still starts a new upstream process per file and uncached path component.

### Example 1 — Single diagnostic (backward compatible)

```bash
python3 sanitize_diag.py original.tar.gz sanitized.tar.gz \
  --cli ./node_modules/.bin/logtotal-sanitize \
  --key-file anonymization.key --config config.json \
  --indexes-conf indexes.conf -i inventory/production.yml
```

### Example 2 — All diagnostics in a directory

```bash
python3 sanitize_diag.py --input-dir ./diags/ --output-dir ./sanitized/ \
  --cli ./node_modules/.bin/logtotal-sanitize \
  --key-file anonymization.key --config config.json \
  --indexes-conf indexes.conf -i inventory/production.yml
```

The directory scan is nonrecursive and selects `.tar.gz` and `.tgz` files in sorted filename order. Use a dedicated input directory containing only the intended diagnostics.

### Example 3 — Explicit selection and exported inventory

```bash
python3 sanitize_diag.py --input cm.tar.gz idx01.tar.gz sh01.tar.gz \
  --output-dir ./sanitized-case-123/ \
  --cli ./node_modules/.bin/logtotal-sanitize \
  --key-file anonymization.key --config config.json \
  --indexes-conf indexes.conf --inventory-json inventory-export.json
```

The output directory is created if needed. Output names are numbered in input order (`diag-0001.tar.gz`, `diag-0002.tar.gz`, etc.), not derived from sensitive original names. Each archive has its own `.tar.gz.json` report; `batch-report.json` contains aggregate counts and completion status. Keep the input order internally if a mapping to original components is needed. Existing outputs are never overwritten. Use a new directory for each run. Duplicate input paths and identical input/output directories in directory mode are rejected. The live progress line shows the archive number, completed archives and current archive's candidate-file count.

A batch stops on the first failure with a nonzero exit status. Previously completed archives remain, and a batch report marks a processing failure when possible. The batch is not transactional; do not release partial outputs without review. Setup failures may occur before a batch report exists.

### Example 4 — Ansible controller batch task

After collecting all diagnostics into a dedicated controller directory, run this in the collection play **after all transfers have completed**, without `serial` on that play (or use a separate controller play). All paths in this example must already be defined in your playbook variables; the inventory export and index export must exist on the controller.

```yaml
- name: Sanitize collected diagnostics in one batch
  ansible.builtin.command:
    argv:
      - python3
      - "{{ diag_anonymizer_home }}/sanitize_diag.py"
      - --input-dir
      - "{{ diag_input_dir }}"
      - --output-dir
      - "{{ diag_sanitized_dir }}"
      - --cli
      - "{{ diag_anonymizer_home }}/node_modules/.bin/logtotal-sanitize"
      - --key-file
      - "{{ diag_anonymizer_key }}"
      - --config
      - "{{ diag_anonymizer_config }}"
      - --indexes-conf
      - "{{ diag_indexes_conf }}"
      - --inventory-json
      - "{{ diag_inventory_export }}"
  delegate_to: localhost
  become: false
  run_once: true
  no_log: true
```

Use the default linear strategy so the batch task starts only after transfers finish. With `serial`, `run_once` executes once per serial batch, not once for the entire play; use a distinct controller phase instead. Ansible captures command output, so the interactive live bar is not normally visible during this task. A separate controller play must also be included in any `--limit` selection. Keep input and output directories private, and review the reports and sanitized files before release.
