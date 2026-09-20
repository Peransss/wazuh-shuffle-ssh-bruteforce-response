# wazuh-shuffle-ssh-bruteforce-response

This project simulates an SSH brute force attack against an Ubuntu Server VM, detects it in real time using Wazuh (SIEM), and automatically blocks the attacking IP through a Shuffle (SOAR) playbook.
 
## 📌 Background
 
SSH is one of the most commonly targeted services for brute force attacks on internet-facing servers. This project demonstrates a full detect-to-response pipeline for SSH brute force attacks, without manual analyst intervention, while also measuring how much faster the automated response is compared to a manual process.
 
## 🎯 Objectives
 
- Detect repeated SSH login attempts (failed password) on an Ubuntu Server VM using Wazuh
- Build an automated Shuffle playbook that blocks the attacker's IP once it crosses a defined threshold
- Send real-time notifications to the analyst when a block occurs
- Measure Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) compared to a manual process
## 🏗️ Architecture

> **Full deep-dive:** See [`docs/architecture.md`](docs/architecture.md) for detailed components, data flow, detection rules, and Discord notification design.

```
[Attacker: Hydra] --(SSH brute force)--> [Target: Ubuntu Server VM] --> [Wazuh Agent] --> [Wazuh Manager] --> [Shuffle Playbook] --> [Discord #soc-alerts]
```

<details>
<summary>ASCII diagram (fallback)</summary>

```
[Attacker: Hydra] --(SSH brute force)--> [Target: Ubuntu Server VM]
                                                    |
                                          (/var/log/auth.log)
                                                    v
                                          [Wazuh Agent]  --(installed on Ubuntu VM)
                                                    |
                                          (forward log to)
                                                    v
                                          [Wazuh Manager]
                                          (rule 5710/5712 + custom threshold rule)
                                                    |
                                          (alert via webhook/integration)
                                                    v
                                          [Shuffle Playbook]
                                          1. Check IP reputation via AbuseIPDB
                                          2. Block IP (iptables / ufw / firewall)
                                          3. Send notification (Discord Webhook)
                                                    v
                                          [Discord #soc-alerts]
```
</details>
 
## 🛠️ Tools & Stack
 
| Component | Tools |
|---|---|
| Target | Ubuntu Server VM (SSH service) |
| Attack simulation | Hydra |
| SIEM | Wazuh (Manager + Agent on Ubuntu VM) |
| SOAR | Shuffle |
| Threat Intelligence | AbuseIPDB API |
| Notification | Discord Webhook (`#soc-alerts`) |
| Blocking | iptables / ufw (executed via Wazuh active response or a Shuffle SSH command) |
 
## ⚙️ How It Works
 
1. **Target setup** — Ubuntu Server VM with SSH enabled, Wazuh agent installed and connected to the Wazuh Manager
2. **Attack simulation** — Hydra runs a brute force attack against the target VM's SSH port using a username/password wordlist
3. **Detection** — The Wazuh agent reads `/var/log/auth.log`; a built-in SSHD rule or custom rule detects failed password attempts exceeding a threshold (e.g. 5 attempts within 1 minute) from the same IP
4. **Trigger** — Wazuh sends an alert to Shuffle via webhook/integration
5. **Enrichment** — Shuffle checks the attacker's IP reputation via AbuseIPDB
6. **Auto-response** — If the confidence score is high, Shuffle executes the IP block (via an SSH command to the VM running `iptables`/`ufw`, or by triggering Wazuh active response)
7. **Notification** — Shuffle sends an incident summary (IP, timestamp, attempt count, block status) to the analyst via Discord Webhook (`#soc-alerts` embed)
## 📊 Results & Evaluation

| Metric | Manual | Automated (Wazuh + Shuffle) |
|---|---|---|
| MTTD (Mean Time to Detect) | *pending — fill after lab run* | *pending — fill after lab run* |
| MTTR (Mean Time to Respond) | *pending — fill after lab run* | *pending — fill after lab run* |

> **How to measure:** see `docs/architecture.md` §9 (compare `auth.log` first `Failed password` → `alerts.json` `100200`, and `alerts.json` → Shuffle execution log / `iptables` timestamp). Track on the `Host-Only` lab with stopwatch.
> Results will be committed after the next test run; open an issue if you have baseline numbers.
 
## 📸 Documentation
 
- [ ] Screenshot of the Wazuh alert when SSH brute force is detected
- [ ] Screenshot of the Shuffle playbook (workflow diagram)
- [ ] Screenshot of the Discord notification (embed in `#soc-alerts`)
- [ ] `/var/log/auth.log` contents before and after the IP is blocked
- [ ] `iptables -L` / `ufw status` output showing the blocked IP
- [ ] Short demo video (optional, highly recommended)
## 🚀 How to Reproduce

```bash
# 0. Configure secrets (never commit)
cp .env.example .env  # fill ABUSEIPDB_API_KEY, DISCORD_WEBHOOK_URL, TARGET_HOST
# Wazuh Manager: copy wazuh/custom-rules/local_rules.xml → /var/ossec/etc/rules/local_rules.xml
# Target Agent : copy wazuh/ossec-agent-conf/ossec.conf → /var/ossec/etc/ossec.conf (set <address>)

# 1. Run the SSH brute force simulation
hydra -l root -P attack-simulation/wordlist.txt ssh://<target-vm-ip>
# alternative with split lists:
hydra -L attack-simulation/common_username.txt -P attack-simulation/common_password.txt ssh://<target-vm-ip> -t 16

# 1b. Rule test without Hydra (fires 100200: 5 fails/60s)
for i in {1..6}; do logger -t sshd "Failed password for root from 192.168.56.10 port 5${i}000 ssh2"; done

# 2. Monitor alerts in the Wazuh dashboard
# Log in to the Wazuh dashboard > Security Events > filter by rule group "authentication_failures" / rule 100200

# 3. Check playbook execution in Shuffle
# Log in to Shuffle > Workflows > wazuh-shuffle-ssh-bruteforce-response > Executions
# Import: shuffle/playbook-export.json (sanitized; secrets via $env.*)

# 4. Verify the block on the target VM
sudo iptables -L -n --line-numbers | grep <attacker-ip>
# or
sudo ufw status numbered | grep <attacker-ip>
# Rollback:
sudo iptables -D INPUT -s <attacker-ip> -j DROP; sudo ufw delete deny from <attacker-ip>
```
 
## 📁 Repo Structure

```
.
├── wazuh/
│   ├── custom-rules/local_rules.xml   # Custom threshold rules 100200/100201 (Manager)
│   ├── ossec-agent-conf/ossec.conf    # Agent config (log path /var/log/auth.log → Manager)
│   └── ossec.conf                     # Manager config (integration → Shuffle webhook, level 10)
├── shuffle/
│   ├── playbook-export.json                           # Sanitized Shuffle workflow (canonical, secrets via $env.*)
│   └── wazuh-shuffle-ssh-bruteforce-response (11).json # Original export (kept, now also sanitized)
├── attack-simulation/
│   ├── common_username.txt  # 82k usernames (729 KB)
│   ├── common_password.txt  # 1.3M passwords (11 MB)
│   ├── wordlist.txt -> common_password.txt  # compat shim for hydra -P wordlist.txt
│   └── README.md
├── docs/
│   ├── architecture.md       # Detailed architecture (components, flow, Discord design)
│   └── screenshots/          # Diagram-Shuffle.png, Testing_Webhook.png, etc.
├── .env.example
├── .gitignore
└── README.md
```
 
## ⚠️ Ethics & Safety Note
 
Attack simulations were performed only against a self-owned VM in an isolated lab environment (internal NAT network), not against any third-party system or a publicly internet-facing host.
 
## 🔮 Future Work
 
- Integrate with the SQL Injection and Web Shell Upload detection projects (target: a PHP-MySQL application) as part of a larger Automated Incident Response system
- Add adaptive branching (auto-block only on high confidence, otherwise escalate to an analyst)
- Build an MTTD/MTTR visualization dashboard
## 👤 Author
 
Fransiskus Sutanto (Frans)
Informatics Engineering — Universitas Bunda Mulia
