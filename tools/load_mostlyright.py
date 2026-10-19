"""Load the Mostly Right dataset into data/mostlyright/snapshot.sqlite (+ snapshot.sha256). CONTRACTS.md v2 §2.1.

Source: s3://ai-hackathon-datasets-422928733782/MostlyRIght/ (capital I is the real path): CNB + ESMA licence
registers, SEPA Instant and VoP participant lists, EU sanctions (entities), regulator warning lists.
Feeds F-PSP, F-WARNLIST, F-SANCTION and the website_domain leg of F-DOMAIN. Owner: WS-D.
"""
from __future__ import annotations


def load(src: str = "s3://ai-hackathon-datasets-422928733782/MostlyRIght/",
         out_dir: str = "data/mostlyright") -> str:
    """Build the sqlite snapshot; return its sha256 hex (the facts' `prov`)."""
    raise NotImplementedError("TODO WS-D")


def main(argv: list[str] | None = None) -> int:
    raise NotImplementedError("TODO WS-D")


if __name__ == "__main__":
    raise SystemExit(main())
