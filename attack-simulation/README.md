# Attack Simulation

Brute-force SSH against the isolated Ubuntu Target VM (see `docs/architecture.md`).

> **Safety:** Run only against your own VM on the Host-Only/NAT lab network. Never against public hosts.

## Wordlists

- `common_username.txt` (82k entries, 729 KB) — common usernames
- `common_password.txt` (1.3M entries, 11 MB) — common passwords (includes `placeholder` line for Hydra self-tests)
- `wordlist.txt` — **compat shim** for `README.md#How to Reproduce`; points to the password list (`common_password.txt`). Either use `-P` with the real file or the shim:

```bash
ls -l wordlist.txt  # -> common_password.txt (symlink / small wrapper)
```

Full lists are kept for reproducible demos but are large. For quick tests use the samples:

```bash
head -n 100 common_password.txt > /tmp/sample_password.txt
head -n 100 common_username.txt > /tmp/sample_user.txt
```

Or download fresh lists: https://github.com/danielmiessler/SecLists/tree/master/Usernames / Passwords

## Quick Start

```bash
# Target: Ubuntu VM 192.168.56.20:22 (PasswordAuthentication yes for lab only)
# Attacker: Kali with hydra

# 1) Minimal test (no traversal noise)
hydra -l root -P common_password.txt ssh://192.168.56.20

# 2) Using both lists (Hydra will try user:pass combos)
hydra -L common_username.txt -P common_password.txt ssh://192.168.56.20 -t 16 -f

# 3) Compat shim (as in README)
hydra -l root -P wordlist.txt ssh://192.168.56.20

# 4) Rule testing without Hydra (generates 5 events in <60s to fire rule 100200)
for i in {1..6}; do logger -t sshd "Failed password for root from 192.168.56.10 port 5${i}000 ssh2"; done
tail -f /var/ossec/logs/alerts/alerts.json | jq 'select(.rule.id=="100200")'
```

## Verify Blocking on Target

```bash
sudo iptables -L -n --line-numbers | grep 192.168.56.10
sudo ufw status numbered | grep 192.168.56.10
# Rollback
sudo iptables -D INPUT -s 192.168.56.10 -j DROP
sudo ufw delete deny from 192.168.56.10
```

## Notes

- `.gitignore` keeps the large wordlists ignored if you want a slim clone; remove the comment to enforce.
- `placeholder` entries exist so Hydra has a known-good dummy when testing parsing.
