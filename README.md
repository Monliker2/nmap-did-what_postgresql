# nmap-did-what (PostgreSQL Edition)

This is a **PostgreSQL-compatible fork** of the original [nmap-did-what](https://github.com/hackertarget/nmap-did-what/) project by [HackerTarget](https://github.com/hackertarget). The goal of this project is to provide a simple and lightweight dashboard to visualize and track results from `nmap` scans, but using **PostgreSQL** as the database backend instead of SQLite.

![Screenshot_03-Jul_23-00-26_16776](https://github.com/user-attachments/assets/2b1b3019-618b-4814-a583-7722f473f3a7)

---

## Differences from the Original

- Switched from SQLite to **PostgreSQL**.
- Updated the `nmap-to-sqlite.py` script for PostgreSQL compatibility.
- Modified the dashboard code to connect and query PostgreSQL.

---

## Setup Instructions
1. Clone the Repository

```bash
git clone https://github.com/Monliker2/nmap-did-what_postgresql.git
cd nmap-did-what_postgresql
```
2. Create a PostgreSQL database:
```bash
CREATE DATABASE nmapdb;
```
4. Import Nmap XML Data

Use nmap to scan a target and save the output in XML format (-oA file):

Example:
```bash
sudo nmap -A --script=http-title,ssl-cert -oA myoutput 192.168.1.0/24
```
5. Import `nmap_dashboard.json` in grafana

Then import it:
```bash
python3 nmap-to-postgre.py --db-password "password" myoutput.xml
```
---
You can also automate this process with cron or custom scripts.



## Credits
- Original project by [HackerTarget](https://github.com/hackertarget)
- PostgreSQL adaptation and Grafana support by [Monliker2](https://github.com/Monliker2)
