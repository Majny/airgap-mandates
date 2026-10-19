"""Supervisor view: one self-contained static HTML page over an audit export, for an auditor to open offline.

The page is a viewer around tools.verify_audit.verify (CONTRACTS.md v2 §7.5): verdict banner, keys (pinned or not),
one row per checkpoint with each signer (log, W1, W2) checked individually, event counts, uncovered-tail status and
skipped checks. No JavaScript, no external fonts or URLs, ASCII-only output; every bundle-derived string is escaped.
W2 is the "independent supervisor witness (simulated operator)". Owner: WS-B.

    python -m witness.supervisor bundle.json [--trust-keys FILE] [-o out.html]
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from typing import Any

from executor.audit import checkpoint as cp
from tools import verify_audit as va

GREEN, AMBER, RED = "#067647", "#b54708", "#b42318"  # WS-F palette
SIGNERS = (("log", "log"), ("w1", "W1"), ("w2", "W2 - independent supervisor witness (simulated operator)"))
MAX_PROBLEMS = 10

CSS = f"""
body {{ font-family: system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; font-size: 20px;
  line-height: 1.4; margin: 0; padding: 24px; background: #ffffff; color: #101828; }}
h1 {{ font-size: 32px; margin: 0 0 16px; }}
h2 {{ font-size: 26px; margin: 32px 0 12px; }}
.banner {{ color: #ffffff; padding: 20px 24px; border-radius: 8px; margin: 0 0 16px; }}
.banner .verdict {{ font-size: 56px; font-weight: 800; letter-spacing: 2px; }}
.banner ol {{ margin: 8px 0 0; padding-left: 28px; }}
.banner li {{ margin: 4px 0; }}
.verified {{ background: {GREEN}; }}
.failed {{ background: {RED}; }}
.seq {{ font-weight: 800; background: rgba(255,255,255,0.25); padding: 0 4px; border-radius: 4px; }}
table {{ border-collapse: collapse; margin: 8px 0; }}
th, td {{ border: 1px solid #d0d5dd; padding: 6px 12px; text-align: left; vertical-align: top; }}
th {{ background: #f2f4f7; }}
td.ok {{ color: {GREEN}; font-weight: 700; }}
td.missing {{ color: {AMBER}; font-weight: 700; }}
td.bad {{ color: {RED}; font-weight: 700; }}
td.neutral {{ color: #475467; font-weight: 700; }}
code {{ font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 18px; }}
.warn {{ color: {AMBER}; font-weight: 700; }}
.good {{ color: {GREEN}; font-weight: 700; }}
.err {{ color: {RED}; font-weight: 700; }}
.small {{ font-size: 16px; color: #475467; }}
"""


def _e(value: Any) -> str:
    """HTML-escape any value (bundle-derived strings are untrusted)."""
    return html.escape(str(value), quote=True)


def _seq_marked(problem: str) -> str:
    """Escape a problem line and highlight its leading 'seq N' so it is visible from the back of the room."""
    text = _e(problem)
    if text.startswith("seq ") and ":" in text:
        head, rest = text.split(":", 1)
        return f'<span class="seq">{head}</span>:{rest}'
    return text


def _signer_keys(bundle: dict[str, Any], trusted: dict[str, str] | None) -> dict[str, tuple[str, bool]]:
    """role -> (vkey, pinned). A pinned key wins; a bundle key is used only for display when the role is not pinned."""
    pub = bundle.get("pubkeys") if isinstance(bundle.get("pubkeys"), dict) else {}
    out = {}
    for role, _ in SIGNERS:
        if trusted and trusted.get(role):
            out[role] = (str(trusted[role]), True)
        elif pub.get(role):
            out[role] = (str(pub[role]), False)
    return out


def signer_status(note: Any, vkey: str) -> str:
    """'OK' / 'missing' / 'BAD' for one signer on one note, checked against that signer's key alone."""
    try:
        k = cp.parse_vkey(vkey)
        parsed = cp.parse_note(note)
    except Exception:  # noqa: BLE001 - unparseable note: not attributable to this signer
        return "malformed"
    if not any(s["name"] == k["name"] and s["key_id"] == k["key_id"] for s in parsed["signatures"]):
        return "missing"
    try:
        v = cp.verify_note(note, [vkey])
    except Exception:  # noqa: BLE001 - parsed fine, so the failure is this signer's line
        return "BAD"
    return "OK" if k["name"] in v["verified"] else "missing"


def _checkpoint_rows(bundle: dict[str, Any], keys: dict[str, tuple[str, bool]], pinning: bool) -> list[str]:
    roles = [(r, label) for r, label in SIGNERS if r in keys]
    head = "".join(f"<th>{_e(label)}{'' if keys[r][1] else ' (unpinned)'}</th>" for r, label in roles)
    rows = [f"<tr><th>created order</th><th>size</th><th>root hash</th>{head}</tr>"]
    notes = bundle.get("checkpoints") if isinstance(bundle.get("checkpoints"), list) else []
    for i, note in enumerate(notes):
        try:
            p = cp.parse_note(note)
            size, root = str(p["size"]), p["root_hash"][:16] + "..."
        except Exception:  # noqa: BLE001 - any unparseable note is shown as such
            size, root = "?", "malformed note"
        cells = []
        for role, _ in roles:
            st = signer_status(note, keys[role][0])
            if st == "OK" and pinning and not keys[role][1]:
                st = "self-asserted"  # some keys are pinned, this one only comes from the bundle
            cls = {"OK": "ok", "BAD": "bad", "missing": "missing"}.get(st, "neutral")
            cells.append(f'<td class="{cls} sig-{role}">{st}</td>')
        rows.append(f'<tr id="cp-{i}"><td>#{i}</td><td>{_e(size)}</td><td><code>{_e(root)}</code></td>'
                    f'{"".join(cells)}</tr>')
    return rows


def _event_counts(bundle: dict[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    leaves = bundle.get("leaves")
    for le in leaves if isinstance(leaves, list) else []:
        ev = le.get("event") if isinstance(le, dict) else None
        counts[str(ev.get("type")) if isinstance(ev, dict) else "(malformed leaf)"] += 1
    return counts


def render_html(bundle: dict[str, Any], trusted_vkeys: dict[str, str] | None = None, *,
                title: str = "AirGap Mandates - audit log supervisor view", replay: bool = True,
                allow_uncovered_tail: bool = False) -> str:
    """Self-contained HTML5 page (inline CSS, no JS, ASCII only) over verify(bundle, replay=, trusted_vkeys=).

    `replay=False` skips the decide() replay (shown as a SKIPPED note); synthetic test logs need it because their
    decision leaves carry no data.inputs. No host banner here: the host UI adds its own (WS-F); this page is meant
    to be generated offline. The verdict element is id="verdict" with data-ok="true|false"."""
    if not isinstance(bundle, dict):
        bundle = {}
        rep = va.Report(False, ["bundle is not a JSON object"])
    else:
        try:
            rep = va.verify(bundle, replay=replay, trusted_vkeys=trusted_vkeys,
                            allow_uncovered_tail=allow_uncovered_tail)
        except Exception as exc:  # noqa: BLE001 - a malformed bundle must give a red page, not a traceback
            rep = va.Report(False, [f"malformed bundle ({type(exc).__name__}: {exc})"])
    keys = _signer_keys(bundle, trusted_vkeys)
    c = rep.checked
    out = ["<!DOCTYPE html>", '<html lang="en"><head><meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>{_e(title)}</title><style>{CSS}</style></head><body>", f"<h1>{_e(title)}</h1>"]
    if rep.ok:
        skipped = f" ({len(rep.notes)} skipped check(s) or warning(s), see below)" if rep.notes else ""
        out.append('<div class="banner verified" id="verdict" data-ok="true"><div class="verdict">VERIFIED</div>'
                   f"<div>{c.get('leaves', 0)} leaves, {c.get('checkpoints', 0)} checkpoints, all performed checks "
                   f"passed{skipped}{'' if rep.pinned else ' (keys not pinned)'}</div></div>")
    else:
        items = "".join(f"<li>{_seq_marked(p)}</li>" for p in rep.problems[:MAX_PROBLEMS])
        more = (f"<div>... and {len(rep.problems) - MAX_PROBLEMS} more problem(s)</div>"
                if len(rep.problems) > MAX_PROBLEMS else "")
        out.append(f'<div class="banner failed" id="verdict" data-ok="false"><div class="verdict">FAILED</div>'
                   f"<div>{len(rep.problems)} problem(s):</div><ol>{items}</ol>{more}</div>")
    out.append(f'<p>log <code>{_e(bundle.get("log_id", "?"))}</code> - {c.get("leaves", 0)} leaves, '
               f'{c.get("checkpoints", 0)} checkpoints, decide() replay {"on" if replay else "off"}</p>')

    out.append("<h2>Keys</h2>")
    used = ", ".join(f"{r} {k}" for r, k in rep.keys.items()) or "none"
    if rep.pinned:
        out.append(f'<p class="good">keys pinned (trusted out of band): <code>{_e(used)}</code></p>')
    else:
        out.append(f"<p>keys in use: <code>{_e(used)}</code></p><p class=\"warn\">keys taken from the bundle (not "
                   "pinned): whoever can rewrite the bundle can re-sign it; pin with --trust-keys</p>")

    out.append("<h2>Checkpoints</h2><table>")
    out += _checkpoint_rows(bundle, keys, pinning=bool(trusted_vkeys))
    out.append("</table><p class=\"small\">Each signer is checked on its own against its key: OK = valid signature, "
               "missing = no line from that key, BAD = a line from that key that does not verify, self-asserted = "
               "valid under a bundle-supplied (unpinned) key, malformed = the note itself does not parse.</p>")

    out.append("<h2>Coverage</h2>")
    unc = c.get("uncovered_leaves")
    if unc is None:
        out.append('<p class="err">coverage not computed (see problems)</p>')
    elif unc == 0:
        out.append(f'<p class="good">every leaf is covered by a witnessed checkpoint ({c.get("covered_leaves", 0)} '
                   "covered; only the trailing checkpoint leaf may wait for the next checkpoint)</p>")
    else:
        out.append(f'<p class="err" id="uncovered">{unc} leaves NOT covered by a witnessed checkpoint '
                   f'(covered: {c.get("covered_leaves", 0)})</p>')

    out.append("<h2>Events by type</h2><table><tr><th>type</th><th>count</th></tr>")
    out += [f"<tr><td>{_e(t)}</td><td>{n}</td></tr>" for t, n in sorted(_event_counts(bundle).items())]
    out.append("</table>")

    if rep.notes:
        out.append("<h2>Skipped checks and warnings</h2><ul>")
        out += [f'<li class="warn">{_e(n)}</li>' for n in rep.notes]
        out.append("</ul>")
    out.append('<p class="small">Static page, no scripts. Generated offline from the exported bundle by '
               "witness/supervisor.py around tools/verify_audit.py.</p></body></html>")
    # ASCII-only output: any non-ASCII character left (e.g. from a bundle string) becomes a numeric reference
    return "\n".join(out).encode("ascii", "xmlcharrefreplace").decode("ascii") + "\n"


def main(argv: list[str] | None = None) -> int:
    """CLI; exit 0 whenever a page was written (the verdict is in the page), 2 if the input cannot be read."""
    ap = argparse.ArgumentParser(prog="python -m witness.supervisor", description="Supervisor view (static HTML)")
    ap.add_argument("bundle", help="audit export JSON (GET /audit/export response)")
    ap.add_argument("--trust-keys", metavar="FILE", help='pinned verifier keys, JSON {"log", "w1", "w2"?}')
    ap.add_argument("-o", "--output", metavar="FILE", help="write the page here (default: stdout)")
    ap.add_argument("--no-replay", action="store_true", help="skip decide() replay")
    ap.add_argument("--allow-uncovered-tail", action="store_true", help="as tools.verify_audit")
    args = ap.parse_args(argv)
    try:
        with open(args.bundle, encoding="utf-8") as f:
            bundle = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"supervisor: cannot read {args.bundle}: {exc}", file=sys.stderr)
        return 2
    if isinstance(bundle, dict) and "response" in bundle and "leaves" not in bundle:
        bundle = bundle["response"]  # contracts fixture envelope
    trusted = None
    if args.trust_keys:
        try:
            trusted = va._load_trust_keys(args.trust_keys)
        except (OSError, ValueError) as exc:
            print(f"supervisor: --trust-keys {args.trust_keys}: {exc}", file=sys.stderr)
            return 2
    page = render_html(bundle, trusted, replay=not args.no_replay, allow_uncovered_tail=args.allow_uncovered_tail)
    if args.output:
        with open(args.output, "w", encoding="ascii") as f:
            f.write(page)
    else:
        sys.stdout.write(page)
    return 0


if __name__ == "__main__":
    sys.exit(main())
