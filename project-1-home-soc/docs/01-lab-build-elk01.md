# Step 3 — Stand up ELK01 (Ubuntu + Docker + Elastic Stack)

**Prereq (done):** DC01 (`lab.local`) is live and verified.
**Goal of this step:** an Ubuntu VM running a single-node Elastic Stack (Elasticsearch + Kibana) in Docker, heap-capped, reachable from your host browser.

ELK01 spec (locked): **2 vCPU · 4 GB RAM · 40 GB thin disk · VMnet8 (NAT)**.

> **Docker Engine, not Docker Desktop.** Install Docker *inside* this Ubuntu VM. Docker Desktop on Windows Home would flip on WSL2 / the Windows Hypervisor Platform and drop your Windows VMs onto a slower hypervisor. Keeping Docker in the guest avoids that entirely.

---

## 3.1 — Create the VM in VMware Workstation

1. **Download** Ubuntu Server 24.04 LTS ISO: https://ubuntu.com/download/server
2. VMware → **Create a New Virtual Machine** → *Typical*.
3. Point it at the Ubuntu ISO.
4. Name it `ELK01`; choose a sensible folder on your data drive.
5. **Disk:** 40 GB, **"Store virtual disk as a single file"**, and tick **"Allocate all disk space" OFF** so it stays *thin* (grows only as used).
6. **Customize Hardware** before finishing:
   - **Memory:** 4096 MB
   - **Processors:** 2
   - **Network Adapter:** **NAT** (this is VMnet8 — same network DC01 sits on)
7. Finish, then **power on** to boot the installer.

## 3.2 — Install Ubuntu Server

Walk the text installer. Notes that matter:

- **Keyboard:** US layout (matches your physical keyboard).
- **Network:** leave DHCP for now — note the IPv4 address it gets (you'll see it on the config screen). Call it `ELK01_IP`.
- **Storage:** use the whole disk (the 40 GB virtual one). Default LVM is fine.
- **Profile:** create your admin user (e.g. `analyst`). Remember the password.
- **"Install OpenSSH server":** **tick this** — it makes life far easier (you can paste commands from your host terminal).
- Skip the featured snaps.

Let it install, then **Reboot Now**. Log in at the console (or SSH in from the host: `ssh analyst@ELK01_IP`).

## 3.3 — Pin the IP (recommended)

A drifting DHCP lease will break Kibana's URL and Fleet later. Reserve/fix the address. Quickest lab approach — find your VMnet8 subnet in VMware (**Edit → Virtual Network Editor → VMnet8**), then set a static lease via netplan. Example (adjust the subnet octet to match VMnet8, and keep it outside the DHCP pool):

```bash
sudo nano /etc/netplan/50-cloud-init.yaml
```

```yaml
network:
  version: 2
  ethernets:
    ens33:                      # confirm your NIC name with:  ip a
      dhcp4: no
      addresses: [192.168.__.20/24]   # ELK01 — pick .20; DC01 is .10
      routes:
        - to: default
          via: 192.168.__.2            # VMnet8 gateway
      nameservers:
        addresses: [192.168.__.10, 1.1.1.1]   # DC01 first so lab.local resolves
```

```bash
sudo netplan apply
ip a            # confirm the new address
```

> Record `ELK01_IP` in your lab notes. From here on it's `192.168.__.20` in examples.

## 3.4 — Update + kernel setting for Elasticsearch

```bash
sudo apt update && sudo apt -y upgrade

# Elasticsearch refuses to start unless this is raised. Set it now and make it stick.
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-elasticsearch.conf
```

## 3.5 — Install Docker Engine (official repo)

```bash
# Prereqs + Docker's GPG key
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repo
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Run docker without sudo (log out/in afterward for it to take effect)
sudo usermod -aG docker "$USER"
newgrp docker

# Sanity check
docker --version
docker compose version
docker run --rm hello-world
```

## 3.6 — Drop in the starter kit and configure

Copy the `elk/` folder from this repo onto ELK01 (git clone, `scp`, or a shared folder). Then:

```bash
cd elk
cp .env.example .env
nano .env
```

In `.env`, set at minimum:
- `ELASTIC_PASSWORD` and `KIBANA_PASSWORD` → two long, **different** passphrases.
- `KIBANA_PUBLIC_URL` → `http://192.168.__.20:5601` (your real ELK01 IP).

> **Do not commit `.env`.** It's git-ignored on purpose. Keep the real passwords in your out-of-band notes, same place as the DC01 credentials.

## 3.7 — Bring the stack up

```bash
chmod +x bring-up.sh verify.sh
./bring-up.sh
```

First run pulls ~2 GB of images and generates certificates — give it a few minutes. You'll see the `setup` container create a CA and node cert, wait for Elasticsearch, set the `kibana_system` password, then say **"All done"**. Elasticsearch then reports it's healthy.

`Ctrl-C` stops *watching* the logs; the containers keep running.

## 3.8 — Verify (your Step 3 exit criteria)

```bash
./verify.sh
```

You want:
- `es01` and `kibana` both **Up (healthy)**.
- Cluster health `status` = `yellow` (normal for a single node — replicas can't be assigned, that's expected) or `green`.

Then from your **host browser**: `http://192.168.__.20:5601`
Log in as user **`elastic`** with your `ELASTIC_PASSWORD`. You should land on the Kibana home page.

**Screenshot this** — the Kibana login working plus the healthy cluster is your first publishable artifact for the repo.

---

## Everyday operation (16 GB discipline)

| Action | Command (run in `elk/`) |
|---|---|
| Start | `docker compose up -d` |
| Stop (keep data) | `docker compose down` |
| Status | `docker compose ps` |
| Follow logs | `docker compose logs -f es01` |
| Wipe everything (indices + certs) | `docker compose down -v` |

**Golden rule:** don't leave ELK01 running alongside DC01 **and** CLIENT01 except during an active attack→detect cycle. Power idle VMs off. Snapshot ELK01 now that it's clean.

---

## Troubleshooting

- **`es01` exits immediately / `max virtual memory areas` error** → you skipped 3.4. Run the `vm.max_map_count` commands, then `docker compose up -d`.
- **`setup` loops on "Waiting for Elasticsearch"** → es01 is probably OOM-restarting. Lower `ES_HEAP` to `1g` in `.env`, then `docker compose down && docker compose up -d`.
- **Kibana unreachable from host** → confirm `KIBANA_PORT` is `5601`, the VM IP is right, and no host firewall is blocking. `curl -I http://localhost:5601` on ELK01 itself first to isolate.
- **Whole stack sluggish / swapping** → 4 GB is tight. For active work you can bump ELK01 to 5–6 GB in VMware (VM must be powered off to change RAM); the 16 GB host has room when CLIENT01 is off.

## What's next

- **Step 4:** install Sysmon (+ SwiftOnSecurity config) on DC01.
- **Step 5:** add **Fleet Server** to this same compose stack and enroll an **Elastic Agent** on DC01 to ship Windows Security + Sysmon logs. (This is why security/TLS is enabled now — Fleet requires it.)
- **Step 6 (milestone):** find your own `4624` logon event in Kibana; commit the README, network diagram, and screenshot.
