"""A throwaway vault for one eval run. Never touches ~/.tabularium/default."""

from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

from tabularium_client import Vault


@contextmanager
def scratch_vault(name: str = "eval"):
    """Yields a fresh Vault in a temp directory, deleted on exit even if the body raises.

    The vault's check-path root is pinned to a sibling `proj/` directory (`vault.root`), so
    relative file_hash/file_exists/symbol_in_file checks resolve there regardless of the
    caller's own working directory -- not to whatever the CWD happened to be at init time.
    """
    tmp = Path(tempfile.mkdtemp(prefix="tabularium-eval-"))
    # Guard against a future refactor accidentally pointing this at a real vault directory.
    assert ".tabularium" not in str(tmp), f"refusing to use a real-looking vault path: {tmp}"
    try:
        root_dir = tmp / "proj"
        root_dir.mkdir(parents=True, exist_ok=True)
        vault_dir = tmp / "vault"
        v = Vault.init(vault_dir, name=name, root=root_dir)
        v.root = root_dir
        yield v
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
