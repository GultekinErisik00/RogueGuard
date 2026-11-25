---
name: vm-lab-ops
description: >-
  Runbook for operating the RogueGuard Ubuntu VM lab over SSH: syncing code
  without overwriting the live SQLite database, running pytest, managing the
  daemon in tmux, inspecting router nftables/leases and SQLite tables, and
  recovering after VM suspend. Use when running tests, live verification, or
  lab maintenance on the VM.
---

# RogueGuard VM Lab Operations

## 1. Verify VM Connection

Always verify SSH and passwordless sudo before running lab commands:

```bash
ssh rogue 'hostname && whoami && sudo -n true && echo SUDO_OK'
```

Expected output: `rogueguard-lab`, `rogue`, `SUDO_OK`. If unreachable, stop and ask the user (VM may be suspended or its DHCP IP may have changed).

## 2. Sync Code (Mac → VM)

Never overwrite `data/` (contains the live `rogueguard.db` inventory):

```bash
rsync -a --exclude .venv --exclude .git --exclude .obsidian --exclude .agents --exclude data ./ rogue:~/rogueguard/
```

## 3. Run Unit Tests on VM

Always invoke pytest via the VM venv module form:

```bash
ssh rogue 'cd ~/rogueguard && .venv/bin/python -m pytest -q'
```

Single test:

```bash
ssh rogue 'cd ~/rogueguard && .venv/bin/python -m pytest -q tests/test_decision.py::test_name'
```

## 4. Run Daemon in tmux

Never use `pkill -f` over SSH (it can kill the SSH command itself). Use `tmux`:

```bash
# Start protect daemon in detached tmux session
ssh rogue 'tmux new -d -s rg "cd ~/rogueguard && sudo .venv/bin/python -m rogueguard protect"'

# Inspect recent logs
ssh rogue 'tmux capture-pane -pt rg -S -50'

# Stop cleanly
ssh rogue 'tmux kill-session -t rg'
```

## 5. Inspect SQLite DB & Router State

SQLite (`sqlite3` CLI is not installed on VM):

```bash
ssh rogue "cd ~/rogueguard && .venv/bin/python -c \"import sqlite3; c=sqlite3.connect('data/rogueguard.db'); print(c.execute('SELECT mac, ip, hostname, status, device_type FROM devices').fetchall())\""
```

Router nftables sets & DHCP leases:

```bash
ssh rogue 'incus exec rg-router -- nft list table inet rg'
ssh rogue 'incus exec rg-router -- cat /var/lib/misc/dnsmasq.leases'
```

## 6. Recovery After VM Suspend

If containers lose internet after VMware Fusion suspend/resume (`incusbr0` loses IPv4):

```bash
ssh rogue 'sudo systemctl restart incus && incus exec rg-router -- networkctl reconfigure eth0'
```

## 7. Host nftables Safety

Never run `nft flush ruleset` on the VM host. If `inet incus` rules are ever accidentally wiped, restore with:

```bash
ssh rogue 'sudo systemctl restart incus'
```
