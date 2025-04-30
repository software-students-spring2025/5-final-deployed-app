import pytest
from unittest.mock import MagicMock
from flask import redirect
import sys
sys.path.append("frontend-app")
import app
import db.mongo_client as mongo_client

@pytest.fixture(autouse=True)
def mock_everything(monkeypatch):
    """
    - Patch pymongo.MongoClient so no real DB calls ever happen.
    - Patch module-level mongo_client.client to the same fake.
    - Patch oauth.google.authorize_redirect to return a Flask redirect
      (avoids AsyncMock in JSON).
    """

    # --- MongoDB mock ---
    fake_client     = MagicMock(name="MongoClient()")
    fake_db         = MagicMock(name="fake_db")
    fake_collection = MagicMock(name="fake_collection")

    # client['any_db'] -> fake_db
    fake_client.__getitem__.return_value = fake_db
    # fake_db['any_coll'] -> fake_collection
    fake_db.__getitem__.return_value = fake_collection

    # Apply to pymongo.MongoClient()
    monkeypatch.setattr("pymongo.MongoClient", MagicMock(return_value=fake_client))
    # And also override your mongo_client.client
    monkeypatch.setattr(mongo_client, "client", fake_client)

    # --- Google OAuth mock ---
    # oauth.google.authorize_redirect(url) -> Flask redirect(url)
    monkeypatch.setattr(
        app.oauth.google,
        "authorize_redirect",
        lambda url: redirect(url)
    )
