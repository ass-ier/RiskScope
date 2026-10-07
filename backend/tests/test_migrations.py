import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import create_engine, inspect


def test_real_alembic_upgrade_and_foreign_keys(tmp_path):
    root = Path(__file__).resolve().parents[1]
    path = tmp_path / "migration.db"
    env = {**os.environ, "RISKSCOPE_DATABASE_URL": f"sqlite:///{path}"}
    for command in (["upgrade", "head"], ["check"]):
        subprocess.run([sys.executable, "-m", "alembic", *command], cwd=root, env=env,
                       check=True, capture_output=True, text=True)
    engine = create_engine(f"sqlite:///{path}")
    inspector = inspect(engine)
    assert len(inspector.get_table_names()) >= 35
    assert inspector.get_foreign_keys("vulnerability_match")
    assert inspector.get_indexes("risk_assessment")
    assert inspector.get_unique_constraints("software_installation")
    engine.dispose()
