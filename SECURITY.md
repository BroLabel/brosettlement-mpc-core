# Security Policy

## Supported Versions

| Version        | Supported |
| -------------- | --------- |
| `main`         | Yes       |
| older releases | No        |

We currently provide security fixes only for the latest code on `main`.

## Reporting a Vulnerability

Do not file public GitHub issues for security vulnerabilities.

This repository contains reusable MPC/TSS building blocks. A vulnerability here can affect downstream signing systems through incorrect protocol behavior, unsafe transport handling, or exposure of key material, so we treat reports with high priority.

### How to report

Send an email to **security@brolabel.io** with:

- a short description of the issue
- steps to reproduce
- affected component or flow
- impact and severity assessment, if known
- your name or handle if you want credit

If you want to share encrypted details, mention that in the email and we can coordinate a secure follow-up channel.

## Response Timeline

| Stage                   | Target                        |
| ----------------------- | ----------------------------- |
| Initial acknowledgement | 48 hours                      |
| Severity assessment     | 5 business days               |
| Fix or mitigation plan  | 15 business days              |
| Disclosure timing       | Coordinated with the reporter |

We follow coordinated disclosure and ask for reasonable time to investigate and fix the issue before public disclosure.

## Scope

### In scope

- key generation and signing flow correctness
- unsafe defaults or API behavior that can lead to unauthorized signing in downstream systems
- key share confidentiality
- share encryption and decryption
- key material remaining in memory longer than intended
- session framing or transport flaws that break protocol integrity
- vulnerabilities in cryptographic or signing dependencies
- storage or file handling issues involving share material

### Out of scope

- vulnerabilities in infrastructure outside this repository
- purely theoretical attacks with no practical exploit path
- denial of service issues unless they also expose key material
- documentation or test-only issues without security impact

## Threat Model

This project assumes:

- applications embedding this module may run in partially trusted environments
- the network is untrusted
- downstream integrations are responsible for deployment-specific authentication, authorization, and key management policy

Issues that make unilateral signing easier, break intended threshold assumptions, or expose secret material are critical.

## Severity Classification

| Severity | Examples                                                            |
| -------- | ------------------------------------------------------------------- |
| Critical | Private key reconstruction, broken threshold assumptions, or protocol flaws enabling unilateral signing |
| High     | Key share leakage, unsafe transport or framing behavior, failure to clear sensitive material            |
| Medium   | Insecure defaults, side-channel leakage with practical impact, misuse-prone API behavior                |
| Low      | Minor weaknesses without a practical exploit path                                                          |

## Bug Bounty

We do not currently run a formal bug bounty program. We may offer public recognition or discretionary rewards for significant findings.

## Hall of Fame

Thank you to the researchers who disclose issues responsibly.
