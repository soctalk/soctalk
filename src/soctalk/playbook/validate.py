"""Author-side playbook validation (#44): the same fail-closed checks the
registry loader applies, as a CLI, so a playbook file is proven valid BEFORE it
is deployed:

    python -m soctalk.playbook.validate path/to/playbook.yaml [more.yaml ...]

Exit code 0 = every file valid; 1 = at least one rejected (reasons on stderr).
"""

from __future__ import annotations

import sys
from pathlib import Path

from soctalk.playbook.registry import load_playbook_file


def main(argv: list[str] | None = None) -> int:
    paths = argv if argv is not None else sys.argv[1:]
    if not paths:
        print("usage: python -m soctalk.playbook.validate <playbook.yaml> [...]",
              file=sys.stderr)
        return 2
    failed = False
    for p in paths:
        try:
            pb = load_playbook_file(Path(p))
        except Exception as exc:  # noqa: BLE001 — report every reason, fail closed
            print(f"REJECTED {p}: {exc}", file=sys.stderr)
            failed = True
            continue
        print(
            f"OK {p}: id={pb.id} version={pb.version} status={pb.status} "
            f"tenant={pb.tenant} priority={pb.priority} "
            f"guardrails={len(pb.guardrails)}"
        )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
