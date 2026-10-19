// Policy set 3 of 3 (CONTRACTS §6.1, R0): may the executor issue a CHG challenge for this change?
// Evaluated when a change would enter SIG_CLERK and again before every CHG challenge.
// Deny => no challenge (the device stays dark); rule_ids = determining forbid @ids.

@id("P-CHG")
permit (principal is Change, action == Action::"issue_chg_challenge", resource is Payee);

@id("I-ATTEST")
forbid (principal is Change, action == Action::"issue_chg_challenge", resource)
when { principal.in_network && !principal.break_glass && context.attest_count < 2 };

@id("I-CALLBACK")
forbid (principal is Change, action == Action::"issue_chg_challenge", resource)
when { (!principal.in_network || principal.break_glass) && !context.callback_confirmed };

@id("I-COOLOFF")
forbid (principal is Change, action == Action::"issue_chg_challenge", resource)
when { context.now < principal.not_before };

@id("I-BLOCK")
forbid (principal is Change, action == Action::"issue_chg_challenge", resource)
when { context.block_hit };
