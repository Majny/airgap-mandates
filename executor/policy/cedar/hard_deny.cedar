// Policy set 1 of 3 (CONTRACTS §2.2, §8.1): hard deny for payments.
// Evaluated alone. Decision Deny <=> some forbid below is determining => outcome "deny".
// P-BASE makes the set default-allow so that only the forbids decide.

@id("P-BASE")
permit (principal is Mandate, action == Action::"pay", resource is Payee);

@id("I-PAYEE")
forbid (principal, action == Action::"pay", resource is Payee)
when { !resource.known || !resource.active };

@id("I-DUP")
forbid (principal, action == Action::"pay", resource)
when { context.dup };

@id("I-BLOCK")
forbid (principal, action == Action::"pay", resource)
when { context.block_hit };
