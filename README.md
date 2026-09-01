# wazuh-shuffle-ssh-bruteforce-response
Proyek ini mensimulasikan serangan brute force SSH pada VM Ubuntu Server, mendeteksinya secara real-time menggunakan Wazuh (SIEM), dan melakukan pemblokiran IP secara otomatis melalui playbook Shuffle (SOAR).
 
## 📌 Latar Belakang
 
SSH adalah salah satu service yang paling sering jadi target brute force di server yang terekspos ke internet. Proyek ini menunjukkan alur deteksi-hingga-respons (detect-to-response) otomatis terhadap serangan brute force SSH, tanpa intervensi manual analyst, sekaligus mengukur seberapa cepat sistem bereaksi dibandingkan proses manual.
 
## 🎯 Tujuan
 
- Mendeteksi percobaan login SSH berulang (failed password) pada VM Ubuntu Server menggunakan Wazuh
- Membangun playbook otomatis di Shuffle yang memblokir IP penyerang setelah melewati threshold tertentu
- Mengirim notifikasi real-time ke analyst saat blokir terjadi
- Mengukur Mean Time to Detect (MTTD) dan Mean Time to Respond (MTTR) dibanding proses manual
## 🏗️ Arsitektur
 
```
[Attacker: Hydra] --(SSH brute force)--> [Target: VM Ubuntu Server]
                                                    |
                                          (/var/log/auth.log)
                                                    v
                                          [Wazuh Agent]  --(installed on Ubuntu VM)
                                                    |
                                          (forward log to)
                                                    v
                                          [Wazuh Manager]
                                          (rule 5710/5712 + custom rule threshold)
                                                    |
                                          (alert via webhook/integration)
                                                    v
                                          [Shuffle Playbook]
                                          1. Cek reputasi IP di AbuseIPDB
                                          2. Block IP (iptables / ufw / firewall)
                                          3. Kirim notifikasi (Telegram/Slack/Email)
                                                    v
                                          [Analyst Notification]
```
 
## 🛠️ Tools & Stack
 
| Komponen | Tools |
|---|---|
| Target | VM Ubuntu Server (SSH service) |
| Simulasi serangan | Hydra |
| SIEM | Wazuh (Manager + Agent di Ubuntu VM) |
| SOAR | Shuffle |
| Threat Intelligence | AbuseIPDB API |
| Notifikasi | Telegram Bot API |
| Blocking | iptables / ufw (dieksekusi via Wazuh active response atau Shuffle SSH command) |
 
## ⚙️ Cara Kerja
 
1. **Setup target** — VM Ubuntu Server dengan SSH service aktif, Wazuh agent terinstal dan terhubung ke Wazuh Manager
2. **Simulasi serangan** — Hydra menjalankan brute force terhadap port SSH VM target dengan wordlist username/password
3. **Deteksi** — Wazuh agent membaca `/var/log/auth.log`, rule bawaan (SSHD) atau custom rule mendeteksi jumlah failed password melebihi threshold (misal 5x dalam 1 menit) dari IP yang sama
4. **Trigger** — Wazuh mengirim alert ke Shuffle lewat webhook/integration
5. **Enrichment** — Shuffle mengecek reputasi IP penyerang via AbuseIPDB
6. **Auto-response** — Jika confidence score tinggi, Shuffle mengeksekusi block IP (via SSH command ke VM untuk menjalankan `iptables`/`ufw`, atau memicu Wazuh active response)
7. **Notifikasi** — Shuffle mengirim ringkasan insiden (IP, waktu, jumlah percobaan, status block) ke Telegram/Slack analyst
## 📊 Hasil & Evaluasi
 
| Metrik | Manual | Otomatis (Wazuh + Shuffle) |
|---|---|---|
| MTTD (Mean Time to Detect) | *isi setelah pengujian* | *isi setelah pengujian* |
| MTTR (Mean Time to Respond) | *isi setelah pengujian* | *isi setelah pengujian* |
 
> Catatan: isi tabel di atas dengan hasil pengujian aktual (bandingkan waktu deteksi manual oleh analyst vs waktu deteksi otomatis oleh Wazuh, dan waktu respons manual vs otomatis oleh Shuffle).
 
## 📸 Dokumentasi
 
- [ ] Screenshot Wazuh alert saat SSH brute force terdeteksi
- [ ] Screenshot Shuffle playbook (workflow diagram)
- [ ] Screenshot notifikasi Telegram/Slack
- [ ] Isi `/var/log/auth.log` sebelum dan sesudah IP diblokir
- [ ] Output `iptables -L` / `ufw status` menunjukkan IP ter-block
- [ ] Video demo singkat (opsional, sangat direkomendasikan)
## 🚀 Cara Menjalankan (Reproduksi)
 
```bash
# 1. Jalankan simulasi brute force SSH
hydra -l root -P wordlist.txt ssh://<target-vm-ip>
 
# 2. Pantau alert di Wazuh dashboard
# Login ke Wazuh dashboard > Security Events > filter by rule group "authentication_failures"
 
# 3. Cek eksekusi playbook di Shuffle
# Login ke Shuffle > Workflows > lihat execution log
 
# 4. Verifikasi blocking di VM target
sudo iptables -L -n | grep <attacker-ip>
# atau
sudo ufw status | grep <attacker-ip>
```
 
## 📁 Struktur Repo
 
```
.
├── wazuh/
│   ├── custom-rules/         # Custom rule XML untuk deteksi SSH brute force
│   └── ossec-agent-conf/     # Konfigurasi agent (log path /var/log/auth.log)
├── shuffle/
│   └── playbook-export.json  # Export workflow Shuffle
├── attack-simulation/
│   └── wordlist.txt
├── docs/
│   └── screenshots/
└── README.md
```
 
## ⚠️ Catatan Etika & Keamanan
 
Simulasi serangan hanya dilakukan pada VM milik sendiri dalam lingkungan lab tertutup (isolated network / NAT internal), bukan terhadap sistem pihak ketiga atau yang terekspos ke internet publik.
 
## 🔮 Pengembangan Selanjutnya
 
- Integrasi dengan proyek deteksi SQL Injection dan Web Shell Upload (target: aplikasi PHP-MySQL) sebagai bagian dari sistem Automated Incident Response yang lebih besar
- Menambahkan adaptive branching (auto-block hanya jika confidence tinggi, selain itu eskalasi ke analyst)
- Dashboard visualisasi MTTD/MTTR
## 👤 Author
 
Fransiskus Sutanto (Frans)
Informatics Engineering — Universitas Bunda Mulia
