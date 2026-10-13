"""Read-only, refreshing local catalog snapshots for long-lived hosts."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .catalog import CatalogError, LocalCatalog
from .contracts import ContractError, regular_file_under


def _metadata(path: Path) -> tuple:
    info = path.lstat()
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode)


class CatalogSnapshot:
    """Cache validated bytes, refresh on mutations, and never serve a stale failure.

    The optional lock is the host's existing writer lock; readers neither create
    it nor migrate the catalog. Exact source metadata participates in refresh,
    so a changed file requires full digest validation before another selection.
    """

    def __init__(self, root: Path, *, lock_path: Path | None = None, maximum_manifests: int = 2000):
        if type(maximum_manifests) is not int or maximum_manifests < 1:
            raise CatalogError("catalog snapshot bound must be a positive integer")
        self.root = Path(root).resolve()
        self.lock_path = lock_path
        self.maximum_manifests = maximum_manifests
        self._catalog: LocalCatalog | None = None
        self._fingerprint: tuple | None = None

    @contextmanager
    def _reader(self) -> Iterator[None]:
        lock = None
        try:
            if self.lock_path is not None:
                try:
                    lock = os.open(
                        self.lock_path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
                    )
                except FileNotFoundError:
                    pass  # No writer has created the existing host lock yet.
                if lock is not None:
                    if os.name != "posix" or not stat.S_ISREG(os.fstat(lock).st_mode):
                        raise CatalogError("catalog reader lock is unavailable or unsafe")
                    import fcntl

                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
            yield
        except (OSError, ContractError) as error:
            raise CatalogError("catalog snapshot is unavailable or changing") from error
        finally:
            if lock is not None:
                os.close(lock)

    def _metadata(self, catalog: LocalCatalog | None) -> tuple:
        root_info = self.root.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            raise CatalogError("catalog snapshot root must be a real directory")
        manifests = sorted(self.root.glob("*/capsule.json"))
        if len(manifests) > self.maximum_manifests:
            raise CatalogError("catalog snapshot exceeds its supported bound")
        entries = []
        current = {manifest.parent for manifest in manifests}
        for manifest in manifests:
            if manifest.parent.is_symlink() or not stat.S_ISREG(manifest.lstat().st_mode):
                raise CatalogError("catalog snapshot manifest is unsafe")
            entries.append((str(manifest), _metadata(manifest.parent), _metadata(manifest)))
        if catalog is not None:
            for capsule in catalog._capsules:
                if capsule.root is None or capsule.root not in current:
                    continue
                for offer in capsule.record["offers"]:
                    if offer["kind"] != "exact-component":
                        continue
                    for source in offer["files"]:
                        try:
                            path = regular_file_under(capsule.root, source["source"], "snapshot source")
                            value = _metadata(path)
                        except (OSError, ContractError):
                            value = ("unavailable",)
                        entries.append((str(capsule.root / source["source"]), value))
        return (_metadata(self.root), tuple(entries))

    def snapshot(self) -> LocalCatalog:
        with self._reader():
            before = self._metadata(self._catalog)
            if self._catalog is not None and before == self._fingerprint:
                return self._catalog
            catalog = LocalCatalog(self.root) if before[1] else LocalCatalog.empty(self.root)
            after = self._metadata(catalog)
            if after != before:
                # New manifests may introduce exact source paths absent from
                # the preceding snapshot. Validate against that expanded
                # fingerprint before caching; never bind post-change metadata
                # to bytes verified before the change.
                catalog = LocalCatalog(self.root) if after[1] else LocalCatalog.empty(self.root)
                current = self._metadata(catalog)
                if current != after:
                    raise CatalogError("catalog changed while validating its snapshot")
                after = current
            self._catalog = catalog
            self._fingerprint = after
            return catalog
