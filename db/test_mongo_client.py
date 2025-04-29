import unittest
from unittest.mock import patch, MagicMock
import mongo_client  # import your actual module name

class TestMongoClient(unittest.TestCase):

    @patch('mongo_client.MongoClient')
    def test_get_db(self, mock_mongo_client):
        # Setup
        mock_client_instance = MagicMock()
        mock_db = MagicMock()
        mock_client_instance.__getitem__.return_value = mock_db
        mock_mongo_client.return_value = mock_client_instance
        
        # Force reload client after patch
        with patch('mongo_client.client', mock_client_instance):
            db = mongo_client.get_db()
            self.assertEqual(db, mock_db)
            mock_client_instance.__getitem__.assert_called_with('project5_db')

    @patch('mongo_client.MongoClient')
    def test_get_user_collection(self, mock_mongo_client):
        # Setup
        mock_client_instance = MagicMock()
        mock_db = MagicMock()
        mock_collection = MagicMock()

        mock_db.__getitem__.return_value = mock_collection
        mock_client_instance.__getitem__.return_value = mock_db
        mock_mongo_client.return_value = mock_client_instance

        with patch('mongo_client.client', mock_client_instance):
            collection = mongo_client.get_user_collection()
            self.assertEqual(collection, mock_collection)
            mock_client_instance.__getitem__.assert_called_with('project5_db')
            mock_db.__getitem__.assert_called_with('userInfo')

if __name__ == '__main__':
    unittest.main()
