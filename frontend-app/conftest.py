import pytest
from unittest.mock import MagicMock
import app  # your Flask app module

@pytest.fixture(autouse=True)
def mock_db_collections(monkeypatch):
    """
    Autouse fixture to mock all MongoDB collections in app.
    This prevents any real network calls and lets tests patch
    collection methods (find_one, insert_one, etc.) directly.
    """
    # Create fake collection objects
    fake_users    = MagicMock(name="users_collection")
    fake_posts    = MagicMock(name="posts_collection")
    fake_comments = MagicMock(name="comments_collection")
    fake_follows  = MagicMock(name="follows_collection")

    # Override the collections in the app module
    monkeypatch.setattr(app, "users_collection",    fake_users)
    monkeypatch.setattr(app, "posts_collection",    fake_posts)
    monkeypatch.setattr(app, "comments_collection", fake_comments)
    monkeypatch.setattr(app, "follows_collection",  fake_follows)

    # Also mock the MongoClient itself in case it’s used elsewhere
    monkeypatch.setattr("pymongo.MongoClient", MagicMock())

    return
