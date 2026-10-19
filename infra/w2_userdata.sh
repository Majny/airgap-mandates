# W2 = unmodified litewitness (filippo.io/torchwood v0.10.0), witness/w2/README.md. Listens on 127.0.0.1:7380 only;
# reached via SSM port forwarding (infra/w2_ctl.sh forward). Key lives in a dedicated ssh-agent.
set -eux
# t4g.nano has 0.5 GB RAM: dnf and the Go build get OOM-killed without swap
if [ ! -f /swapfile ]; then dd if=/dev/zero of=/swapfile bs=1M count=2048; chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile; echo '/swapfile swap swap defaults 0 0' >> /etc/fstab; fi
dnf install -y golang openssh-clients
export HOME=/root GOPATH=/root/go GOBIN=/opt/w2/bin GOTOOLCHAIN=auto  # torchwood v0.10.0 needs go >= 1.27; AL2023 ships 1.26
# AL2023 go.env sets GOSUMDB=off: verify the toolchain and torchwood against the public checksum DB instead
export GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org,direct
mkdir -p /opt/w2/bin /opt/w2/state
go install filippo.io/torchwood/cmd/litewitness@v0.10.0 filippo.io/torchwood/cmd/witnessctl@v0.10.0
[ -f /opt/w2/state/w2key ] || ssh-keygen -q -t ed25519 -N "" -C airgap-w2 -f /opt/w2/state/w2key
cat > /etc/systemd/system/w2-agent.service <<'UNIT'
[Unit]
Description=ssh-agent for litewitness
[Service]
ExecStart=/usr/bin/ssh-agent -D -a /opt/w2/a.sock
ExecStartPost=/bin/sh -c 'sleep 1; SSH_AUTH_SOCK=/opt/w2/a.sock /usr/bin/ssh-add /opt/w2/state/w2key'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/w2.service <<'UNIT'
[Unit]
Description=W2 litewitness
After=w2-agent.service
Requires=w2-agent.service
[Service]
ExecStart=/bin/sh -c 'FP=$(ssh-keygen -lf /opt/w2/state/w2key.pub -E sha256 | cut -d" " -f2); exec /opt/w2/bin/litewitness -db /opt/w2/state/w2.db -name airgap.example/demo/w2 -key "$FP" -ssh-agent /opt/w2/a.sock -listen 127.0.0.1:7380'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now w2-agent.service
# w2.service is started by `infra/w2_ctl.sh trust` after the log vkey has been added with witnessctl
