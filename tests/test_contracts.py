from __future__ import annotations

import json
from pathlib import Path

import pytest
from limitless_library.contracts import ContractError, relative_path, strict_json_loads, write_new_json


def test_strict_json_rejects_duplicate_keys_and_nonfinite_values() -> None:
    with pytest.raises(json.JSONDecodeError):
        strict_json_loads('{"decision":"reuse","decision":"abstain"}')
    with pytest.raises(json.JSONDecodeError):
        strict_json_loads('{"cost":NaN}')


@pytest.mark.parametrize("value", ["../secret", "/absolute", "a/../../b", "./local", "a\\b", ""])
def test_relative_paths_reject_ambiguous_or_escaping_values(value: str) -> None:
    with pytest.raises(ContractError):
        relative_path(value)


def test_immutable_json_write_refuses_overwrite(tmp_path: Path) -> None:
    output = tmp_path / "receipt.json"
    write_new_json(output, {"first": True})
    with pytest.raises(ContractError, match="overwrite"):
        write_new_json(output, {"first": False})
    assert json.loads(output.read_text()) == {"first": True}
