"""Attacker workstation: a separate app (port 8502) that fires real requests at the executor API from outside the
bank, so a jury can see the attacks blocked live on the operations console (port 8501). Owner: WS-F.

`attacker.attacks` is pure, testable logic over a `call(method, path, body, who)` transport (the same shape as
host.signer.executor_call, infra.aws_e2e.signed_call and executor.scenes DemoEnv.call). `attacker.console` is the
Streamlit UI. Everything here is the adversary's side; nothing here is trusted by the executor.
"""
