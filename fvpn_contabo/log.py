from __future__ import annotations

from dataclasses import dataclass

@dataclass
class Logger:
    quiet: bool = False
    debug: bool = False

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(msg)

    def ok(self, msg: str) -> None:
        if not self.quiet:
            print(f"✅ {msg}")

    def warn(self, msg: str) -> None:
        if not self.quiet:
            print(f"⚠️  {msg}")

    def dbg(self, msg: str) -> None:
        if self.debug and not self.quiet:
            print(f"[DBG] {msg}")
