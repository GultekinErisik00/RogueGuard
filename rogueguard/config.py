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


def with_overrides(cfg: dict[str, Any], profile: str | None = None,
                   db_path: str | None = None) -> dict[str, Any]:
    """Deney koşucusu için config kopyası: tespit profili ve veritabanı yolu değiştirilir
    (config.yaml'a dokunmadan; experiments/run_scenarios.py her koşuda kullanır)."""
    out = cfg | {"decision": dict(cfg["decision"]), "database": dict(cfg["database"])}
    if profile:
        out["decision"]["detection_profile"] = profile
    if db_path:
        p = Path(db_path)
        out["database"]["path"] = str(p if p.is_absolute() else ROOT / p)
    return out
