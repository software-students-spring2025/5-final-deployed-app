import pytest
from unittest.mock import MagicMock
from flask import redirect
import app

@pytest.fixture(autouse=True)
def mock_external_services(monkeypatch):
    """
    Autouse fixture to:
      1) Replace pymongo.MongoClient and app.client with a MagicMock,
         so no real MongoDB is ever contacted.
      2) Patch oauth.google.authorize_redirect to return a Flask redirect,
         satisfying TestGoogleLink without AsyncMocks leaking into JSON.
    """

    # --- 1) Mock MongoDB Client ---
    fake_client     = MagicMock(name="MongoClient()")
    fake_database   = MagicMock(name="fake_database")
    fake_collection = MagicMock(name="fake_collection")

    # Any client[...] returns our fake_database
    fake_client.__getitem__.return_value = fake_database
    # Any fake_database[...] returns our fake_collection
    fake_database.__getitem__.return_value = fake_collection

    # Patch pymongo.MongoClient(...) ⇒ fake_client
    monkeypatch.setattr("pymongo.MongoClient", MagicMock(return_value=fake_client))
    # If your code uses a module-level `client = MongoClient(...)`, override it too
    monkeypatch.setattr(app, "client", fake_client)

    # --- 2) Mock Google OAuth redirect ---
    # Replace oauth.google.authorize_redirect(...) ⇒ Flask redirect(...)
    # This avoids AsyncMock objects in the response.
    monkeypatch.setattr(
        app.oauth.google,
        "authorize_redirect",
        lambda uri: redirect(uri)
    )

    return
