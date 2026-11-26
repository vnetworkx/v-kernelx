from __future__ import annotations
import sys
from pathlib import Path

from .runtime import Runtime

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python -m vlangx.prototype <file.vx|file.vdx>")
        raise SystemExit(2)
    path = Path(argv[0])
    source = path.read_text(encoding="utf-8")
    runtime = Runtime()
    report = runtime.execute_source(source)
    for line in report["outputs"]:
        print(line)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
