# Deploying Obscura on a single AWS EC2 instance

This deploys the `apps/demo-ui` Express server (with the bundled `@obscura/core`
engine and the local NER model) as one Docker container on one EC2 instance.
User/session state lives on a Docker volume backed by the instance's EBS disk,
so it survives container rebuilds and reboots.

**Why a single instance:** all app state is on the local filesystem
(`apps/demo-ui/data/`) and the vault is in-process. Autoscaling / multi-instance
setups would split or lose that state without a code refactor (DynamoDB/RDS +
Redis vault). One instance with a persistent disk is the correct fit for the
current design.

---

## 0. Prerequisites (local)

- An AWS account with credits.
- An EC2 key pair (`.pem`) for SSH, or create one during launch.
- The Anthropic API key you want the server to use.

---

## 1. Launch the EC2 instance

Console → EC2 → Launch instance:

| Setting        | Value                                                        |
| -------------- | ----------------------------------------------------------- |
| AMI            | **Ubuntu Server 24.04 LTS** (x86_64)                        |
| Instance type  | **t3.medium** (2 vCPU / 4 GB) — the NER model needs headroom; t3.small/2 GB is the bare minimum and can OOM during model load |
| Key pair       | your `.pem` key                                             |
| Storage        | **20 GB gp3**                                               |
| Security group | see below                                                    |

**Security group inbound rules:**

- SSH `22` — source **My IP** only
- HTTP `80` and HTTPS `443` — source `0.0.0.0/0`  *(needed for the HTTPS/Caddy option)*
- Custom TCP `3000` — source **My IP**  *(only for quick HTTP testing; remove once HTTPS is up)*

Note the instance's **public IP** after it boots.

---

## 2. Get the code onto the instance

**Option A — tarball + scp (simplest, no GitHub auth on the box).**
From your Mac, in the repo root (`/Users/siyamishra/obscura/Obscura`):

```bash
# Build a clean tarball of the repo (excludes node_modules, .git, data, .env)
tar --exclude='./node_modules' --exclude='./**/node_modules' \
    --exclude='./.git' --exclude='./apps/demo-ui/data' \
    --exclude='./.env' --exclude='./**/dist' \
    -czf /tmp/obscura.tgz -C /Users/siyamishra/obscura/Obscura .

# Copy it up (replace KEY.pem and the IP)
scp -i KEY.pem /tmp/obscura.tgz ubuntu@<PUBLIC_IP>:~/

# On the instance:
ssh -i KEY.pem ubuntu@<PUBLIC_IP>
mkdir -p ~/obscura && tar -xzf ~/obscura.tgz -C ~/obscura
```

**Option B — git clone.** Commit and push the deploy files first, then on the
instance `git clone git@github.com:mishrasiya/Obscura.git obscura` (requires a
deploy key or PAT on the instance for this private repo).

---

## 3. Install Docker on the instance

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker   # or log out/in so `docker` works without sudo
```

---

## 4. Configure secrets

```bash
cd ~/obscura
cp .env.example .env
nano .env
```

Set at least:

- `ANTHROPIC_API_KEY` — required.
- `JWT_SECRET` — run `openssl rand -hex 32` and paste the result. **Do this** —
  otherwise the server signs auth cookies with a public hardcoded secret.
- `DOMAIN` — only if you're doing the HTTPS option in step 5b.

---

## 5. Build and run

The first build downloads deps and bakes the NER model into the image — expect
a few minutes.

### 5a. Quick HTTP (test it works)

```bash
docker compose up -d --build
docker compose logs -f app     # wait for: "Obscura demo UI running at ..."
```

Open `http://<PUBLIC_IP>:3000` (port 3000 must be open to your IP).

### 5b. Production HTTPS (recommended)

1. Point a DNS **A record** for your domain at `<PUBLIC_IP>` and wait for it to
   propagate.
2. Set `DOMAIN=your.domain.com` in `.env`.
3. (Optional) remove the `3000:3000` mapping in `docker-compose.yml` so the app
   is only reachable through Caddy.
4. Bring it up with the TLS profile:

```bash
docker compose --profile tls up -d --build
```

Caddy fetches a Let's Encrypt cert automatically. Open `https://your.domain.com`.

---

## 6. Operate

```bash
docker compose logs -f app          # tail logs
docker compose restart app          # restart
docker compose down                 # stop (data volume persists)
docker compose up -d --build        # redeploy after code changes
docker volume inspect obscura_obscura-data   # where state lives
```

To update: re-copy the code (step 2) and re-run `docker compose up -d --build`.

---

## Cost note (against your credits)

A t3.medium is ~\$30/mo on-demand + ~\$2/mo for 20 GB gp3, plus egress. Stop the
instance when idle to conserve credits. There are no other paid AWS services in
this setup (no load balancer, RDS, or EFS) — just the one instance.
