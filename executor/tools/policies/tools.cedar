// A2 tool-scoping policies (CONTRACTS §4.5; defence in depth, never the money gate). Owner: WS-E.
// Served by AgentCore Gateway + Policy (AIRGAP_GATEWAY=agentcore) or the cedarpy twin (local).

@id("T-BASE")
permit (principal is Agent, action == Action::"call", resource is Tool);

@id("T-DECOY")
forbid (principal is Agent, action == Action::"call", resource)
when { resource == Tool::"mandate.write" || resource == Tool::"vendor.write" };

@id("T-MAIL-ALLOWLIST")
forbid (principal is Agent, action == Action::"call", resource == Tool::"mail.send_template")
unless { context.to_allowlisted };

@id("T-MAIL-IBAN")
forbid (principal is Agent, action == Action::"call", resource == Tool::"mail.send_template")
when { context.vars_match_iban };

@id("T-LOOKUP-RATE")
forbid (principal is Agent, action == Action::"call", resource == Tool::"vendor.lookup")
when { context.lookup_count > 5 };
