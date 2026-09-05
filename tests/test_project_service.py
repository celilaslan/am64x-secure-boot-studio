from pathlib import Path
import json

import pytest

from am64x_secure_toolkit.services.project import create_project, open_project


def test_project_workspace_does_not_store_secret_paths(tmp_path: Path):
    project = create_project(tmp_path / "demo", name="Demo", lifecycle="HS-FS")
    loaded = open_project(project.root)
    assert loaded.name == "Demo"
    meta = json.loads((project.root / ".am64x-studio/project.json").read_text())
    assert meta["secret_paths_stored"] is False
    assert "private" not in json.dumps(meta).lower()
    assert "mek" not in json.dumps(meta).lower()


def test_project_init_refuses_existing_metadata(tmp_path: Path):
    root = tmp_path / "demo"
    create_project(root, name="Demo")
    with pytest.raises(FileExistsError):
        create_project(root, name="Again")
