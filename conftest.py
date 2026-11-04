"""pytest bootstrap: put the repository root on sys.path so `import app.cfgparse` works without installing anything.

app/ has no __init__.py: the Docker image copies it flat to /app and runs `uvicorn main:app`, and its modules import
each other by bare name (`import cfgparse`, `from db import db`). From the repo root it is still importable as the
namespace package `app`, which is enough for modules that only need the stdlib (like cfgparse). A test that imports a
module with sibling imports additionally needs app/ itself on sys.path.
"""
import sys
from pathlib import Path

ROOT = str(Path(__file__).resolve().parent)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
