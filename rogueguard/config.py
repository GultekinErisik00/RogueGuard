"""config.yaml'ı okur. Tüm modüller ayarları buradan alır; yollar repo köküne göredir."""
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent


def load(path: Path | None = None) -> dict[str, Any]:
    cfg = yaml.safe_load((path or ROOT / "config.yaml").read_text())
    db_path = Path(cfg["database"]["path"])
    cfg["database"]["path"] = str(db_path if db_path.is_absolute() else ROOT / db_path)
    return cfg
