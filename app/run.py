"""Entry point for uvicorn: `uvicorn app.run:app`."""

from app.main import create_app

app = create_app()
