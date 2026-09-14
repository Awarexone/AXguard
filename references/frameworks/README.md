# Verified framework ID notes

Research date: 2026-09-15  
Verified via official OWASP / CWE / ATLAS / NIST sources.  
Expand only with IDs confirmed on authoritative pages.

## OWASP Top 10:2021

Overview: https://owasp.org/Top10/2021/

| ID | Name | Official URL |
|---|---|---|
| A01:2021 | Broken Access Control | https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/ |
| A02:2021 | Cryptographic Failures | https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/ |
| A03:2021 | Injection | https://owasp.org/Top10/2021/A03_2021-Injection/ |
| A04:2021 | Insecure Design | https://owasp.org/Top10/2021/A04_2021-Insecure_Design/ |
| A05:2021 | Security Misconfiguration | https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/ |
| A06:2021 | Vulnerable and Outdated Components | https://owasp.org/Top10/2021/A06_2021-Vulnerable_and_Outdated_Components/ |
| A07:2021 | Identification and Authentication Failures | https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/ |
| A08:2021 | Software and Data Integrity Failures | https://owasp.org/Top10/2021/A08_2021-Software_and_Data_Integrity_Failures/ |
| A09:2021 | Security Logging and Monitoring Failures | https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/ |
| A10:2021 | Server-Side Request Forgery (SSRF) | https://owasp.org/Top10/2021/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/ |

A 2025 RC exists; skills pin **2021** unless explicitly upgraded.

## OWASP API Security Top 10:2023

Overview: https://owasp.org/API-Security/editions/2023/en/0x11-t10/

| ID | Name |
|---|---|
| API1:2023 | Broken Object Level Authorization |
| API2:2023 | Broken Authentication |
| API3:2023 | Broken Object Property Level Authorization |
| API4:2023 | Unrestricted Resource Consumption |
| API5:2023 | Broken Function Level Authorization |
| API6:2023 | Unrestricted Access to Sensitive Business Flows |
| API7:2023 | Server Side Request Forgery |
| API8:2023 | Security Misconfiguration |
| API9:2023 | Improper Inventory Management |
| API10:2023 | Unsafe Consumption of APIs |

## OWASP Top 10 for LLM Applications:2026 (latest published)

Primary publication: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/  
Project hub: https://owasp.org/www-project-top-10-for-large-language-model-applications/

**Frontmatter policy:** use `LLM0x:2026` only (do not mix 2025 labels).

| ID | Name |
|---|---|
| LLM01:2026 | Prompt Injection |
| LLM02:2026 | Sensitive Information Disclosure |
| LLM03:2026 | Excessive Agency |
| LLM04:2026 | Supply Chain |
| LLM05:2026 | Data and Model Poisoning |
| LLM06:2026 | Unbounded Consumption |
| LLM07:2026 | Misinformation |
| LLM08:2026 | Hidden Context Exposure |
| LLM09:2026 | Vector and Embedding Weaknesses |
| LLM10:2026 | Improper Output Handling |

## OWASP ASVS

| Item | Value |
|---|---|
| Current stable | **5.0.0** |
| Overview | https://owasp.org/www-project-application-security-verification-standard/ |
| Source tag | https://github.com/OWASP/ASVS/tree/v5.0.0 |

Skill `owasp_asvs` stays empty unless a specific requirement ID is cited from ASVS 5.0 text.

## OWASP WSTG

| Item | Value |
|---|---|
| Stable web release | **v4.2** |
| Overview | https://owasp.org/www-project-web-security-testing-guide/ |
| TOC | https://wstg.owasp.org/v4.2/ |

Verified example IDs:

| ID | Name |
|---|---|
| WSTG-INFO-02 | Fingerprint Web Server |
| WSTG-INPV-04 | Testing for HTTP Parameter Pollution |
| WSTG-INPV-05 | Testing for SQL Injection |
| WSTG-SESS-05 | Testing for Cross Site Request Forgery |

Citation form may also appear as `WSTG-v42-…`. v5.0 is in development — do not invent new IDs.

## Common CWEs (cwe.mitre.org)

| ID | Name |
|---|---|
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| CWE-77 | Improper Neutralization of Special Elements used in a Command ('Command Injection') |
| CWE-78 | Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') |
| CWE-79 | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') |
| CWE-89 | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') |
| CWE-94 | Improper Control of Generation of Code ('Code Injection') |
| CWE-209 | Generation of Error Message Containing Sensitive Information |
| CWE-284 | Improper Access Control |
| CWE-287 | Improper Authentication |
| CWE-295 | Improper Certificate Validation |
| CWE-352 | Cross-Site Request Forgery (CSRF) |
| CWE-434 | Unrestricted Upload of File with Dangerous Type |
| CWE-489 | Active Debug Code |
| CWE-494 | Download of Code Without Integrity Check |
| CWE-502 | Deserialization of Untrusted Data |
| CWE-506 | Embedded Malicious Code |
| CWE-611 | Improper Restriction of XML External Entity Reference |
| CWE-639 | Authorization Bypass Through User-Controlled Key |
| CWE-798 | Use of Hard-coded Credentials |
| CWE-862 | Missing Authorization |
| CWE-863 | Incorrect Authorization |
| CWE-918 | Server-Side Request Forgery (SSRF) |
| CWE-942 | Permissive Cross-domain Policy with Untrusted Domains |
| CWE-1321 | Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution') |
| CWE-1336 | Improper Neutralization of Special Elements Used in a Template Engine |

Top 25 overview (2025): https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html

## MITRE ATLAS (collection 2026.08)

Hub: https://atlas.mitre.org/  
Data: https://github.com/mitre-atlas/atlas-data (`ATLAS-2026.08.yaml`)

Verified technique IDs (YAML + atlas.mitre.org routes; bare HTTP GET may 404 due to SPA):

| ID | Name |
|---|---|
| AML.T0051 | LLM Prompt Injection |
| AML.T0054 | LLM Jailbreak |
| AML.T0056 | Extract LLM System Prompt |
| AML.T0061 | LLM Prompt Self-Replication |
| AML.T0068 | LLM Prompt Obfuscation |
| AML.T0093 | Prompt Infiltration via Public-Facing Application |

## NIST AI RMF 1.0

Overview: https://www.nist.gov/itl/ai-risk-management-framework  
PDF: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf  
Core functions (conceptual in skill bodies): **GOVERN / MAP / MEASURE / MANAGE**  
Keep `nist_ai_rmf: []` unless citing official subcategory IDs from NIST AI 100-1.
