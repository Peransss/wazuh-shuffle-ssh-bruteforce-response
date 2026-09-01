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
                                          3. Send notification (Telegram/Slack/Email)
                                                    v
                                          [Analyst Notification]
```
 
## 🛠️ Tools & Stack
 
| Component | Tools |
|---|---|
| Target | Ubuntu Server VM (SSH service) |
| Attack simulation | Hydra |
| SIEM | Wazuh (Manager + Agent on Ubuntu VM) |
| SOAR | Shuffle |
| Threat Intelligence | AbuseIPDB API |
| Notification | Telegram Bot API |
| Blocking | iptables / ufw (executed via Wazuh active response or a Shuffle SSH command) |
 
## ⚙️ How It Works
 
1. **Target setup** — Ubuntu Server VM with SSH enabled, Wazuh agent installed and connected to the Wazuh Manager
2. **Attack simulation** — Hydra runs a brute force attack against the target VM's SSH port using a username/password wordlist
3. **Detection** — The Wazuh agent reads `/var/log/auth.log`; a built-in SSHD rule or custom rule detects failed password attempts exceeding a threshold (e.g. 5 attempts within 1 minute) from the same IP
4. **Trigger** — Wazuh sends an alert to Shuffle via webhook/integration
5. **Enrichment** — Shuffle checks the attacker's IP reputation via AbuseIPDB
6. **Auto-response** — If the confidence score is high, Shuffle executes the IP block (via an SSH command to the VM running `iptables`/`ufw`, or by triggering Wazuh active response)
7. **Notification** — Shuffle sends an incident summary (IP, timestamp, attempt count, block status) to the analyst via Telegram/Slack
## 📊 Results & Evaluation
 
| Metric | Manual | Automated (Wazuh + Shuffle) |
|---|---|---|
| MTTD (Mean Time to Detect) | *fill in after testing* | *fill in after testing* |
| MTTR (Mean Time to Respond) | *fill in after testing* | *fill in after testing* |
 
> Note: fill in the table above with actual test results (compare manual analyst detection time vs. Wazuh's automated detection time, and manual response time vs. Shuffle's automated response time).
 
## 📸 Documentation
 
- [ ] Screenshot of the Wazuh alert when SSH brute force is detected
- [ ] Screenshot of the Shuffle playbook (workflow diagram)
- [ ] Screenshot of the Telegram/Slack notification
- [ ] `/var/log/auth.log` contents before and after the IP is blocked
- [ ] `iptables -L` / `ufw status` output showing the blocked IP
- [ ] Short demo video (optional, highly recommended)
## 🚀 How to Reproduce
 
```bash
# 1. Run the SSH brute force simulation
hydra -l root -P wordlist.txt ssh://<target-vm-ip>
 
# 2. Monitor alerts in the Wazuh dashboard
# Log in to the Wazuh dashboard > Security Events > filter by rule group "authentication_failures"
 
# 3. Check playbook execution in Shuffle
# Log in to Shuffle > Workflows > view execution log
 
# 4. Verify the block on the target VM
sudo iptables -L -n | grep <attacker-ip>
# or
sudo ufw status | grep <attacker-ip>
```
 
## 📁 Repo Structure
 
```
.
├── wazuh/
│   ├── custom-rules/         # Custom rule XML for SSH brute force detection
│   └── ossec-agent-conf/     # Agent config (log path /var/log/auth.log)
├── shuffle/
│   └── playbook-export.json  # Exported Shuffle workflow
├── attack-simulation/
│   └── wordlist.txt
├── docs/
│   └── screenshots/
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
