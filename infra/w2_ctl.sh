#!/usr/bin/env bash
# W2 instance control: start | stop | status | trust <log_vkey> | vkey | forward (127.0.0.1:7380 -> W2). Owner: WS-E.
set -euo pipefail
export AWS_PROFILE=${AWS_PROFILE:-hackathon} AWS_REGION=${AWS_REGION:-eu-central-1}
ID=$(aws cloudformation describe-stacks --stack-name AirgapMandates \
  --query "Stacks[0].Outputs[?OutputKey=='W2InstanceId'].OutputValue" --output text)
run() { aws ssm send-command --instance-ids "$ID" --document-name AWS-RunShellScript \
  --parameters "commands=[\"$1\"]" --query Command.CommandId --output text; }
case "${1:-status}" in
  start) aws ec2 start-instances --instance-ids "$ID" >/dev/null; aws ec2 wait instance-running --instance-ids "$ID" ;;
  stop) aws ec2 stop-instances --instance-ids "$ID" >/dev/null; echo "stopped $ID (EBS only while stopped)" ;;
  status) aws ec2 describe-instances --instance-ids "$ID" --query "Reservations[0].Instances[0].State.Name" --output text ;;
  trust) run "/opt/w2/bin/witnessctl add-log -db /opt/w2/state/w2.db -origin airgap.example/demo/audit; /opt/w2/bin/witnessctl add-key -db /opt/w2/state/w2.db -origin airgap.example/demo/audit -key '$2'; systemctl enable --now w2.service" ;;
  reset) # after reset_state: forget the old log size (keep w2key, so the W2 vkey is unchanged); $2 = log vkey
    run "systemctl stop w2.service; rm -f /opt/w2/state/w2.db /opt/w2/state/w2.db-shm /opt/w2/state/w2.db-wal; /opt/w2/bin/witnessctl add-log -db /opt/w2/state/w2.db -origin airgap.example/demo/audit; /opt/w2/bin/witnessctl add-key -db /opt/w2/state/w2.db -origin airgap.example/demo/audit -key '$2'; systemctl start w2.service" ;;
  vkey) run "journalctl -u w2.service --no-pager | grep -o 'vkey=[^ ]*' | tail -1" ;;
  forward) aws ssm start-session --target "$ID" --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["7380"],"localPortNumber":["7380"]}' ;;
  *) echo "usage: $0 start|stop|status|trust <log_vkey>|reset <log_vkey>|vkey|forward"; exit 2 ;;
esac
