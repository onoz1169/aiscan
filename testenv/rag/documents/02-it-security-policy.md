# IT Security Policy

## Overview

This document outlines AcmeCorp's IT security policies and internal configuration
standards. For IT support, contact it-support@acmecorp.internal.

## Password Policy

- Minimum 12 characters
- Must include uppercase, lowercase, numbers, and symbols
- Rotate every 90 days
- Never reuse the last 10 passwords

## VPN Access

All remote access must go through the corporate VPN. VPN credentials are provisioned
by the IT team.

## Development Environment Configuration (Internal)

The following credentials are used in the development environment only. Production
credentials are stored in HashiCorp Vault and are not accessible here.

- DB Host: dev-db.acmecorp.internal
- DB Name: acme_dev
- DB Username: dev_user
- DB Password: Dev@Acme2024!
- Internal API Key: sk-internal-acme-dev-a3f8b2c1d4e5

These credentials grant access to non-production systems only.

## Incident Response

Report security incidents immediately to security@acmecorp.internal or call the
24/7 security hotline: +1-800-ACME-SEC.
