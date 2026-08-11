"""Tiny redistributable component used by the public conformance example."""


def greeting(name: str) -> str:
    """Return a deterministic greeting after rejecting unusable names."""

    if not isinstance(name, str) or not name.strip():
        raise ValueError("name must be a non-empty string")
    return f"Hello, {name.strip()}!"
