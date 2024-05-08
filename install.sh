#!/bin/bash

sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared bookworm main' | tee /etc/apt/sources.list.d/cloudflared.list

sudo apt update && sudo apt -y install cloudflared cloudflare-warp git

warp-cli registration new
warp-cli mode warp
warp-cli dns families malware
warp-cli connect

if curl https://www.cloudflare.com/cdn-cgi/trace/ 2>&1 | grep -q "warp=on"; then
    echo "WARP Running"
else
    echo "Error WARP is not running"
    exit 1
fi

curl -L https://go.dev/dl/go1.22.2.linux-amd64.tar.gz -o /tmp/go.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm -f /tmp/go.tar.gz
export PATH=$PATH:/usr/local/go/bin

go install github.com/cloudflare/cloudflared/cmd/cloudflared@latest
go install github.com/cloudflare/apt-transport-cloudflared/cmd/cfd@latest

echo "Installing Docker..."
apt update
apt install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common
curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
apt update
apt install -y docker-ce
#
exit 0