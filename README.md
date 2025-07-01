# Wazuh Keycloak SSO Automation

## Overview

This repository contains an automated Bash script (`setup-sso.sh`) that sets up Single Sign-On (SSO) integration between **Wazuh** and **Keycloak** using **OpenID Connect (OIDC)**.

It streamlines:

* Realm creation
* Client & role configuration
* User provisioning
* Wazuh Indexer & Dashboard configuration
* Role mapping with OpenSearch Security
* Service restarts and validation

---

## Features

* End-to-end OIDC integration in one script
* Automatic realm, client, role, and user creation in Keycloak
* Updates Wazuh Indexer and Dashboard config
* Runs `securityadmin.sh` for seamless indexer sync
* Verifies Wazuh services status
* Easily extensible for custom environments

---

## Usage

```bash
git clone https://github.com/<your-org>/wazuh-keycloak-sso-automation.git
cd wazuh-keycloak-sso-automation
chmod +x setup-sso.sh

./setup-sso.sh \
  --keycloak-url https://keycloak.example.com \
  --realm myrealm \
  --client wazuh-openid \
  --admin-user admin \
  --admin-pass adminpass \
  --new-user alice \
  --new-pass Alic3P@ss \
  --new-email alice@example.com \
  --new-firstname Alice \
  --new-lastname Smith \
  --siem_url wazuh.example.com
```

---

## Requirements

* Debian/Ubuntu-based system (supports `apt`)
* Root or sudo privileges
* Packages: `jq`, `curl`, `sed`, `systemctl`
* Network access to:

  * Keycloak server
  * Wazuh Indexer and Dashboard
* Keycloak `admin-cli` credentials

---

## Output

* 🔧 `Realm`, `Client`, `Roles`, `User` created in Keycloak
* OIDC values injected into:

  * `config.yml.keycloak`
  * `opensearch_dashboards.yml`
* Wazuh services restarted
* OpenID login enabled on Wazuh Dashboard

---

## Advanced Tips

* For MFA: Configure it in Keycloak under **Authentication → Flows**
* Role mapping: Ensure `roles_mapping.yml` aligns with roles from Keycloak token
* Extend script: Add additional functions for backup or monitoring hooks

---

## 📄 License

MIT License

---

## Maintainer

Developed and maintained by Yash Patel.

