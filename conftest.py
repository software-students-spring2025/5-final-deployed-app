# conftest.py
import pytest
from unittest.mock import MagicMock
import db.mongo_client as mongo_client

@pytest.fixture(autouse=True)
def fake_mongo(monkeypatch):
    
    fake_client = MagicMock(name="MongoClient()")
    fake_db = MagicMock(name="fake_db")
    fake_collection = MagicMock(name="fake_collection")

    fake_client.__getitem__.return_value = fake_db

    fake_client.get_default_database.return_value = fake_db

    fake_db.__getitem__.return_value = fake_collection
    fake_db.get_collection.return_value = fake_collection

    monkeypatch.setattr("pymongo.MongoClient", MagicMock(return_value=fake_client))
    monkeypatch.setattr(mongo_client, "client", fake_client)

    return fake_client
