// Policy set 2 of 3 (CONTRACTS §2.2, §8.1): mandate allow for payments.
// Evaluated alone, only when set 1 allowed. Allow => outcome "allow" (executed under the mandate).
// Deny => outcome "challenge" (exact-sign step-up); rule_ids = determining forbid @ids,
// or ["I-MANDATE"] when nothing is determining. Principal Mandate::"none" when no ACTIVE mandate; the cap
// rules are guarded by status == "ACTIVE" so that only I-MANDATE (and payee/fact rules) fire then.

@id("P-MANDATE")
permit (principal is Mandate, action == Action::"pay", resource is Payee)
when { principal.status == "ACTIVE" && principal.policy_current };

@id("I-MANDATE")
forbid (principal is Mandate, action == Action::"pay", resource)
unless { principal.status == "ACTIVE" && principal.policy_current };

@id("I-EXP")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (context.now < principal.valid_from || context.now >= principal.valid_until) };

@id("I-PER")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (context.amount_minor > principal.max_per_payment_minor) };

@id("I-BUDGET")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (principal.spent_minor + context.amount_minor > principal.max_total_minor) };

@id("I-COUNT")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (principal.count + 1 > principal.max_count) };

@id("I-REGISTRY")
forbid (principal is Mandate, action == Action::"pay", resource)
when { !context.reg_hit };

@id("I-VOP")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (!principal.require_vop.contains(context.vop)) };

@id("I-ANOM")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (context.anom >= principal.max_anom) };

@id("I-SPLIT")
forbid (principal is Mandate, action == Action::"pay", resource)
when { principal.status == "ACTIVE" && (context.split_count > 0 &&
         context.split_sum + context.amount_minor > principal.max_per_payment_minor) };

@id("I-Z")
forbid (principal is Mandate, action == Action::"pay", resource)
when { context.z_hit };

@id("I-WARN")
forbid (principal is Mandate, action == Action::"pay", resource)
when { context.warn_hit };
