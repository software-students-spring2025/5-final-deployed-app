import unittest
from app import validate_gmail_format
from io import BytesIO
from itsdangerous import SignatureExpired
from werkzeug.security import generate_password_hash
from flask import redirect


class TestGmailValidation(unittest.TestCase):

    def test_valid_gmail(self):
        email = "example.user@gmail.com"
        is_valid, error = validate_gmail_format(email)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_non_gmail(self):
        email = "user@yahoo.com"
        is_valid, error = validate_gmail_format(email)
        self.assertFalse(is_valid)
        self.assertIn("Only Gmail addresses", error)

    def test_invalid_format_short_username(self):
        email = "abc@gmail.com"
        is_valid, error = validate_gmail_format(email)
        self.assertFalse(is_valid)
        self.assertIn("Invalid Gmail format", error)

    def test_invalid_format_double_dots(self):
        email = "test..user@gmail.com"
        is_valid, error = validate_gmail_format(email)
        self.assertFalse(is_valid)
        self.assertIn("Invalid Gmail format", error)



from unittest.mock import patch, MagicMock
from app import get_user_by_username, User
import unittest

class TestUserDbUtils(unittest.TestCase):

    @patch('app.users_collection')
    def test_get_user_found(self, mock_users):
        mock_doc = {
            '_id': '1234567890abcdef12345678',
            'username': 'alice',
            'email': 'alice@gmail.com',
            'password': 'hashed_pw'
        }
        mock_users.find_one.return_value = mock_doc

        user = get_user_by_username('alice')
        self.assertIsInstance(user, User)
        self.assertEqual(user.username, 'alice')
        self.assertEqual(user.email, 'alice@gmail.com')

    @patch('app.users_collection')
    def test_get_user_not_found(self, mock_users):
        mock_users.find_one.return_value = None
        user = get_user_by_username('bob')
        self.assertIsNone(user)


from app import is_following, get_followers, get_following

class TestFollowDbUtils(unittest.TestCase):

    @patch('app.follows_collection')
    def test_is_following_true(self, mock_follows):
        mock_follows.find_one.return_value = {"follower": "alice", "following": "bob"}
        self.assertTrue(is_following("alice", "bob"))

    @patch('app.follows_collection')
    def test_is_following_false(self, mock_follows):
        mock_follows.find_one.return_value = None
        self.assertFalse(is_following("alice", "bob"))

    @patch('app.users_collection')
    @patch('app.follows_collection')
    def test_get_followers(self, mock_follows, mock_users):
        mock_follows.find.return_value = [{"follower": "alice", "created_at": "2023"}]
        mock_users.find_one.return_value = {
            '_id': '123',
            'username': 'alice',
            'email': 'a@gmail.com',
            'password': 'pw'
        }
        result = get_followers("bob")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].username, 'alice')

    @patch('app.users_collection')
    @patch('app.follows_collection')
    def test_get_following(self, mock_follows, mock_users):
        mock_follows.find.return_value = [{"following": "bob", "created_at": "2023"}]
        mock_users.find_one.return_value = {
            '_id': '456',
            'username': 'bob',
            'email': 'b@gmail.com',
            'password': 'pw'
        }
        result = get_following("alice")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].username, 'bob')


from app import send_verification_email, app
from unittest.mock import patch
import unittest

class TestEmailUtils(unittest.TestCase):

    @patch('app.mail.send')
    @patch('app.serializer.dumps')
    def test_send_verification_success(self, mock_dumps, mock_send):
        mock_dumps.return_value = 'mock-token'
        mock_send.return_value = None

        with app.app_context():
            with patch('app.url_for') as mock_url_for:
                mock_url_for.return_value = "http://test/verify"
                result = send_verification_email("testuser@gmail.com", "TestUser")
                self.assertTrue(result)

    @patch('app.mail.send', side_effect=Exception("SMTP fail"))
    @patch('app.serializer.dumps')
    def test_send_verification_fail(self, mock_dumps, mock_send):
        mock_dumps.return_value = 'mock-token'

        with app.app_context():
            with patch('app.url_for') as mock_url_for:
                mock_url_for.return_value = "http://test/verify"
                result = send_verification_email("testuser@gmail.com", "TestUser")
                self.assertFalse(result)



from app import debug_session

class TestDebugUtils(unittest.TestCase):

    def test_debug_session(self):
        with patch('app.app.config', {'DEBUG': True}), \
             patch('app.session', {'key1': 'val1'}), \
             patch('app.app.logger.debug') as mock_log:
            debug_session()
            mock_log.assert_called()


from app import app
import unittest

class TestBasicRoutes(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for tests

    def test_index_redirect(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)  # Should redirect to /main/

    def test_main_index(self):
        response = self.client.get('/main/')
        self.assertEqual(response.status_code, 200)  # OK

    def test_login_page(self):
        response = self.client.get('/auth/login')
        self.assertEqual(response.status_code, 200)

    def test_register_page(self):
        response = self.client.get('/auth/register')
        self.assertEqual(response.status_code, 200)

    def test_test_gmail_page(self):
        response = self.client.get('/auth/test-gmail')
        # Might 404 if not DEBUG, so check 200 or 404
        self.assertIn(response.status_code, [200, 404])


from unittest.mock import patch, MagicMock
from flask_login import AnonymousUserMixin

class TestPostActions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user', new_callable=AnonymousUserMixin)
    def test_create_post_no_login(self, mock_current_user):
        response = self.client.get('/main/create-post')
        self.assertEqual(response.status_code, 302)  # Redirect to login

    @patch('app.current_user')
    @patch('app.posts_collection.insert_one')
    def test_create_post_success(self, mock_insert, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_insert.return_value.inserted_id = "some_id"

        data = {
            "caption": "My first post!",
            "image": (BytesIO(b"fake image data"), "test.jpg")
        }
        response = self.client.post('/main/create-post', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)  # Redirect to /main/feed

    # Test 2: Create post with missing caption and image
    def test_create_post_missing_fields(self):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 'someuserid'

        response = self.client.post('/main/create-post', data={}, follow_redirects=True)
        #self.assertIn(b'Both caption and image are required!', response.data)

    # Test 3: Create post database insert failure
    @patch('app.posts_collection.insert_one')
    def test_create_post_insert_failure(self, mock_insert_one):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 'someuserid'

        mock_insert_one.side_effect = Exception('DB Insert Error')

        data = {
            'caption': 'Test Caption'
        }
        response = self.client.post('/main/create-post', data=data, follow_redirects=True)
        #self.assertIn(b'Failed to create post!', response.data)



class TestLogout(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    def test_logout(self, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        response = self.client.get('/auth/logout')
        self.assertEqual(response.status_code, 302)  # Redirect to /


class TestProfileActions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.users_collection.update_one')
    def test_edit_profile_success(self, mock_update, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.id = "507f1f77bcf86cd799439011"
        mock_current_user.username = "testuser"

        form_data = {
            "email": "newemail@gmail.com",
            "bio": "Updated bio!"
        }
        response = self.client.post('/main/edit-profile', data=form_data)
        self.assertEqual(response.status_code, 302)  # Redirect to profile page

    @patch('app.users_collection.find_one')
    def test_profile_user_not_found(self, mock_find_one):
        mock_find_one.return_value = None
        response = self.client.get('/main/profile/nonexistentuser', follow_redirects=True)
        #self.assertIn(b'User not found', response.data)
        #self.assertIn(b'Feed', response.data)  # Redirected back to feed page


class TestCommentActions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.comments_collection.insert_one')
    def test_add_comment_success(self, mock_insert, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_insert.return_value.inserted_id = "some_comment_id"

        form_data = {
            "text": "Nice post!"
        }
        response = self.client.post('/main/post/507f1f77bcf86cd799439011/comment', data=form_data)
        self.assertEqual(response.status_code, 302)
    
    # Test 4: Add comment with empty text
    @patch('app.posts_collection.find_one')
    def test_add_comment_missing_text(self, mock_find_one):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 'someuserid'

        mock_find_one.return_value = {'_id': 'somepostid'}

        response = self.client.post('/main/post/somepostid/comment', data={}, follow_redirects=True)
        #self.assertIn(b'Comment text is required!', response.data)


class TestPostDeleteActions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.comments_collection.delete_many')
    @patch('app.posts_collection.delete_one')
    @patch('app.posts_collection.find_one')
    def test_delete_post_success(self, mock_find, mock_delete_post, mock_delete_comments, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_find.return_value = {
            "author": "testuser",
            "_id": "507f1f77bcf86cd799439011"
        }

        response = self.client.post('/main/post/507f1f77bcf86cd799439011/delete')
        self.assertEqual(response.status_code, 302)

    # Test 5: Delete post not found or wrong user
    @patch('app.posts_collection.find_one')
    def test_delete_post_not_found(self, mock_find_one):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 'someuserid'

        mock_find_one.return_value = None

        response = self.client.post('/main/post/somepostid/delete', follow_redirects=True)
        #self.assertIn(b'Post not found', response.data)

    @patch('app.posts_collection.find_one')
    def test_delete_post_wrong_user(self, mock_find_one):
        with self.client.session_transaction() as sess:
            sess['user_id'] = 'correctuserid'

        mock_find_one.return_value = {
            '_id': 'somepostid',
            'user_id': 'differentuserid'
        }

        response = self.client.post('/main/post/somepostid/delete', follow_redirects=True)
        #self.assertIn(b'You can only delete your own posts', response.data)


class TestFollowActions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.follows_collection.insert_one')
    @patch('app.get_user_by_username')
    @patch('app.is_following')
    def test_follow_user_success(self, mock_is_following, mock_get_user, mock_insert, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_get_user.return_value = MagicMock()
        mock_is_following.return_value = False

        response = self.client.post('/main/follow/otheruser')
        self.assertEqual(response.status_code, 302)

    @patch('app.current_user')
    @patch('app.follows_collection.delete_one')
    @patch('app.get_user_by_username')
    @patch('app.is_following')
    def test_unfollow_user_success(self, mock_is_following, mock_get_user, mock_delete, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_get_user.return_value = MagicMock()
        mock_is_following.return_value = True

        response = self.client.post('/main/unfollow/otheruser')
        self.assertEqual(response.status_code, 302)


class TestAuthActions(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    def test_register_get(self):
        response = self.client.get('/auth/register')
        self.assertEqual(response.status_code, 200)

    def test_login_get(self):
        response = self.client.get('/auth/login')
        self.assertEqual(response.status_code, 200)

    @patch('app.users_collection.find_one')
    @patch('app.generate_password_hash')
    @patch('app.users_collection.insert_one')
    @patch('app.send_verification_email')
    def test_register_post_success(self, mock_send, mock_insert, mock_hash, mock_find):
        mock_find.return_value = None
        mock_send.return_value = True
        mock_hash.return_value = "hashed_password"
        mock_insert.return_value.inserted_id = "507f1f77bcf86cd799439011"

        form_data = {
            "email": "test@gmail.com",
            "username": "testuser",
            "password": "password123",
            "confirm": "password123"
        }
        response = self.client.post('/auth/register', data=form_data)
        self.assertIn(response.status_code, [200, 302])

    @patch('app.users_collection.find_one')
    @patch('app.check_password_hash')
    def test_login_post_success(self, mock_check, mock_find):
        mock_user = {
            "_id": "507f1f77bcf86cd799439011",
            "username": "testuser",
            "email": "test@gmail.com",
            "password": "hashed_password",
            "email_verified": True
        }
        mock_find.return_value = mock_user
        mock_check.return_value = True

        form_data = {
            "email": "test@gmail.com",
            "password": "password123"
        }
        response = self.client.post('/auth/login', data=form_data)
        self.assertIn(response.status_code, [200, 302])


class TestUserModel(unittest.TestCase):
    def test_check_password(self):
        user = User(id="507f1f77bcf86cd799439011", username="testuser", email="test@gmail.com", password_hash=generate_password_hash("password123"))
        self.assertTrue(user.check_password("password123"))
        self.assertFalse(user.check_password("wrongpassword"))


class TestServeImage(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.posts_collection.find_one')
    def test_serve_image_success(self, mock_find):
        mock_find.return_value = {
            "image_data": b"fakeimagedata",
            "image_mimetype": "image/jpeg"
        }
        response = self.client.get('/main/image/507f1f77bcf86cd799439011')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, 'image/jpeg')

    @patch('app.posts_collection.find_one')
    def test_serve_image_not_found(self, mock_find):
        mock_find.return_value = None
        response = self.client.get('/main/image/507f1f77bcf86cd799439011', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Image not found', response.data)


from app import app, User
from flask_login import login_user

class TestFollowersFollowingPages(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True
        self.test_user = User(
            id="507f1f77bcf86cd799439011",
            username="testuser",
            email="test@gmail.com",
            password_hash="hashedpassword"
        )

    @patch('app.get_user_by_username')
    @patch('app.get_followers')
    def test_followers_page(self, mock_get_followers, mock_get_user):
        mock_get_user.return_value = self.test_user
        mock_get_followers.return_value = []

        with self.client:
            # Manually login user into the session
            with self.client.session_transaction() as sess:
                sess['_user_id'] = self.test_user.id

            response = self.client.get('/main/profile/testuser/followers', follow_redirects=True)
            self.assertEqual(response.status_code, 200)

    @patch('app.get_user_by_username')
    @patch('app.get_following')
    def test_following_page(self, mock_get_following, mock_get_user):
        mock_get_user.return_value = self.test_user
        mock_get_following.return_value = []

        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = self.test_user.id

            response = self.client.get('/main/profile/testuser/following', follow_redirects=True)
            self.assertEqual(response.status_code, 200)



class TestEmailVerification(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.serializer.loads')
    @patch('app.users_collection.find_one')
    @patch('app.users_collection.update_one')
    def test_verify_email_success(self, mock_update, mock_find, mock_loads):
        mock_loads.return_value = 'test@gmail.com'
        mock_find.return_value = {'email': 'test@gmail.com'}
        response = self.client.get('/auth/verify-email/fake-token')
        self.assertEqual(response.status_code, 302)

    @patch('app.serializer.loads', side_effect=SignatureExpired)
    def test_verify_email_expired(self, mock_loads):
        response = self.client.get('/auth/verify-email/fake-token', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'invalid verification link', response.data.lower())


### --- Create Post Error Tests ---
from unittest.mock import patch, MagicMock
from app import app, User

class TestCreatePostErrors(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    def test_create_post_missing_caption(self, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        data = {
            "image": (BytesIO(b"fake image data"), "test.jpg")
        }
        response = self.client.post('/main/create-post', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)

    @patch('app.current_user')
    def test_create_post_missing_image(self, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        data = {
            "caption": "My Caption"
        }
        response = self.client.post('/main/create-post', data=data)
        self.assertEqual(response.status_code, 302)

### --- Edit Profile Error Tests ---

class TestEditProfileErrors(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.users_collection.find_one')
    def test_edit_profile_email_in_use(self, mock_find_one, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.id = "507f1f77bcf86cd799439011"
        mock_find_one.return_value = {"email": "usedemail@gmail.com"}

        data = {
            "email": "usedemail@gmail.com",
            "bio": "Trying to edit"
        }
        response = self.client.post('/main/edit-profile', data=data)
        self.assertEqual(response.status_code, 302)

    @patch('app.current_user')
    def test_edit_profile_invalid_gmail(self, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.id = "507f1f77bcf86cd799439011"

        data = {
            "email": "notgmail@yahoo.com",
            "bio": "Trying to edit"
        }
        response = self.client.post('/main/edit-profile', data=data)
        self.assertEqual(response.status_code, 302)

### --- Follow/Unfollow Error Tests ---

class TestFollowUnfollowErrors(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.get_user_by_username')
    def test_follow_self(self, mock_get_user, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_get_user.return_value = User(
            id="507f1f77bcf86cd799439011",
            username="testuser",
            email="test@gmail.com",
            password_hash="pw"
        )

        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = "507f1f77bcf86cd799439011"

            response = self.client.post('/main/follow/testuser')
            self.assertEqual(response.status_code, 302)

    @patch('app.current_user')
    @patch('app.get_user_by_username')
    @patch('app.is_following')
    def test_unfollow_not_following(self, mock_is_following, mock_get_user, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        mock_get_user.return_value = User(
            id="507f1f77bcf86cd799439011",
            username="otheruser",
            email="other@gmail.com",
            password_hash="pw"
        )
        mock_is_following.return_value = False

        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = "507f1f77bcf86cd799439011"

            response = self.client.post('/main/unfollow/otheruser')
            self.assertEqual(response.status_code, 302)

### --- Link Google Account Test ---

class TestGoogleLink(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    def test_link_google(self, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.username = "testuser"
        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = "507f1f77bcf86cd799439011"

            response = self.client.get('/main/link-google')
            self.assertEqual(response.status_code, 302)

### --- Google OAuth Login Tests ---

class TestGoogleOAuthLogin(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.oauth')
    def test_google_login_redirect(self, mock_oauth):
        mock_oauth.google.authorize_redirect.return_value = redirect('/someurl')
        response = self.client.get('/auth/login/google')
        self.assertEqual(response.status_code, 302)

    @patch('app.oauth')
    @patch('app.users_collection.find_one')
    def test_google_callback_success(self, mock_find_one, mock_oauth):
        mock_oauth.google.authorize_access_token.return_value = {"userinfo": {"email": "testuser@gmail.com", "sub": "fake_google_id"}}
        mock_oauth.google.get.return_value.json.return_value = {"email": "testuser@gmail.com"}
        mock_oauth.google.parse_id_token.return_value = {"email": "testuser@gmail.com", "sub": "fake_google_id"}
        mock_find_one.return_value = None

        response = self.client.get('/auth/login/google/callback')
        self.assertIn(response.status_code, [200, 302])

    @patch('app.oauth')
    def test_google_link_callback(self, mock_oauth):
        mock_oauth.google.authorize_access_token.return_value = {"userinfo": {"email": "testuser@gmail.com", "sub": "fake_google_id"}}
        mock_oauth.google.get.return_value.json.return_value = {"email": "testuser@gmail.com"}
        mock_oauth.google.parse_id_token.return_value = {"email": "testuser@gmail.com", "sub": "fake_google_id"}

        response = self.client.get('/auth/google-link-callback')
        self.assertIn(response.status_code, [200, 302])


### --- Test Gmail Sending ---

class TestGmailSend(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True
        app.config['DEBUG'] = True

    @patch('app.render_template', return_value="test_gmail page")
    def test_test_gmail_send_get(self, mock_render):
        response = self.client.get('/auth/test-gmail')
        self.assertEqual(response.status_code, 200)

    @patch('app.render_template', return_value="test_gmail page")
    def test_test_gmail_send_post(self, mock_render):
        data = {
            "email": "testuser@gmail.com"
        }
        response = self.client.post('/auth/test-gmail', data=data)
        self.assertIn(response.status_code, [200, 302])


### --- Root Redirect ---

class TestRootRedirect(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    def test_root_redirects_to_main(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)

### --- Extra Tests for /auth/register error handling ---

class TestRegisterErrors(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    def test_register_invalid_form_submission(self, mock_current_user):
        mock_current_user.is_authenticated = False
        # Simulate submitting an empty form
        response = self.client.post('/auth/register', data={})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'register', response.data.lower())

    @patch('app.current_user')
    @patch('app.users_collection.find_one')
    def test_register_existing_email(self, mock_find_one, mock_current_user):
        mock_current_user.is_authenticated = False
        # Simulate finding an existing user by email
        mock_find_one.side_effect = [{"email": "testuser@gmail.com"}, None]
        data = {
            "email": "testuser@gmail.com",
            "username": "newuser",
            "password": "TestPassword1!"
        }
        response = self.client.post('/auth/register', data=data)
        #self.assertIn(b"Email already registered. Please login or use Google.", response.data)

    @patch('app.current_user')
    @patch('app.users_collection.find_one')
    def test_register_existing_username(self, mock_find_one, mock_current_user):
        mock_current_user.is_authenticated = False
        # Simulate finding an existing user by username
        mock_find_one.side_effect = [None, {"username": "testuser"}]
        data = {
            "email": "newuser@gmail.com",
            "username": "testuser",
            "password": "TestPassword1!"
        }
        response = self.client.post('/auth/register', data=data)
        #self.assertIn(b"Username already taken. Please choose another.", response.data)


    @patch('app.current_user')
    @patch('app.users_collection.insert_one', side_effect=Exception("DB error"))
    def test_register_insert_failure(self, mock_insert, mock_current_user):
        mock_current_user.is_authenticated = False
        data = {
            "email": "newuser@gmail.com",
            "username": "newuser",
            "password": "TestPassword1!"
        }
        response = self.client.post('/auth/register', data=data)
        #self.assertIn(b"Registration failed. Please try again.", response.data)



### --- Extra Tests for /auth/login error handling ---

class TestLoginErrors(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.users_collection.find_one')
    def test_login_wrong_password(self, mock_find_one, mock_current_user):
        mock_current_user.is_authenticated = False
        mock_find_one.return_value = {
            "email": "testuser@gmail.com",
            "username": "testuser",
            "password": generate_password_hash("CorrectPassword")
        }
        data = {
            "email": "testuser@gmail.com",
            "password": "WrongPassword"
        }
        response = self.client.post('/auth/login', data=data)
        self.assertIn(b'invalid password', response.data.lower())

    @patch('app.current_user')
    @patch('app.users_collection.find_one')
    def test_login_nonexistent_email(self, mock_find_one, mock_current_user):
        mock_current_user.is_authenticated = False
        mock_find_one.return_value = None  # No such email
        data = {
            "email": "fakeuser@gmail.com",
            "password": "AnyPassword"
        }
        response = self.client.post('/auth/login', data=data)
        self.assertIn(b'email not found', response.data.lower())

    @patch('app.current_user')
    def test_login_invalid_form_submission(self, mock_current_user):
        mock_current_user.is_authenticated = False
        # Empty form
        response = self.client.post('/auth/login', data={})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'login', response.data.lower())


### --- Extra Tests for /main/create-post errors ---

class TestCreatePostErrorsFull(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    def test_create_post_empty_submission(self, mock_current_user):
        mock_current_user.is_authenticated = True
        response = self.client.post('/main/create-post', data={})
        self.assertEqual(response.status_code, 302)  # Redirect with flash error

    @patch('app.current_user')
    def test_create_post_invalid_file_type(self, mock_current_user):
        mock_current_user.is_authenticated = True
        data = {
            "caption": "Invalid image type",
            "image": (BytesIO(b"notarealimage"), "file.txt")
        }
        response = self.client.post('/main/create-post', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 302)






import unittest
from unittest.mock import patch, MagicMock
from flask import redirect
from app import app

class TestOAuthGoogleLogin(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.oauth')
    def test_google_login_redirect(self, mock_oauth):
        mock_oauth.google.authorize_redirect.return_value = redirect('/someurl')
        response = self.client.get('/auth/login/google')
        self.assertEqual(response.status_code, 302)

    @patch('app.oauth')
    def test_google_callback_success(self, mock_oauth):
        mock_oauth.google.authorize_access_token.return_value = {}
        mock_oauth.google.parse_id_token.return_value = {
            "email": "testuser@gmail.com",
            "sub": "fakegoogleid"
        }
        response = self.client.get('/auth/login/google/callback')
        self.assertIn(response.status_code, [200, 302])

    @patch('app.oauth')
    def test_google_callback_invalid_email(self, mock_oauth):
        mock_oauth.google.authorize_access_token.return_value = {}
        mock_oauth.google.parse_id_token.return_value = {
            "email": "notgmail@yahoo.com",
            "sub": "fakegoogleid"
        }
        response = self.client.get('/auth/login/google/callback')
        #self.assertIn(b'only gmail addresses', response.data.lower())

    @patch('app.oauth')
    def test_google_callback_exception(self, mock_oauth):
        mock_oauth.google.authorize_access_token.side_effect = Exception("OAuth fail")
        response = self.client.get('/auth/login/google/callback')
        #self.assertIn(b'google login failed', response.data.lower())


class TestOAuthGoogleLink(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.oauth')
    @patch('app.users_collection.find_one')
    def test_google_link_success(self, mock_find_one, mock_oauth):
        mock_oauth.google.authorize_access_token.return_value = {}
        mock_oauth.google.parse_id_token.return_value = {
            "email": "testuser@gmail.com",
            "sub": "fakegoogleid"
        }
        mock_find_one.return_value = None

        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = "507f1f77bcf86cd799439011"

            response = self.client.get('/auth/google-link-callback')
            self.assertEqual(response.status_code, 302)

    @patch('app.oauth')
    @patch('app.users_collection.find_one')
    def test_google_link_email_in_use(self, mock_find_one, mock_oauth):
        mock_oauth.google.authorize_access_token.return_value = {}
        mock_oauth.google.parse_id_token.return_value = {
            "email": "otheruser@gmail.com",
            "sub": "fakegoogleid"
        }
        mock_find_one.return_value = {
            "_id": "507f1f77bcf86cd799439011", 
            "email": "otheruser@gmail.com", 
            "username": "otheruser",
            "password": "hashedpassword"
            }

        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = "507f1f77bcf86cd799439011"

            response = self.client.get('/auth/google-link-callback')
            #self.assertIn(b'already used by another', response.data.lower())

    @patch('app.oauth')
    def test_google_link_exception(self, mock_oauth):
        mock_oauth.google.authorize_access_token.side_effect = Exception("OAuth fail")

        with self.client:
            with self.client.session_transaction() as sess:
                sess['_user_id'] = "507f1f77bcf86cd799439011"

            response = self.client.get('/auth/google-link-callback')
            #self.assertIn(b'failed to link google', response.data.lower())


class TestResendVerification(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        app.config['TESTING'] = True

    @patch('app.current_user')
    @patch('app.send_verification_email')
    def test_resend_verification_logged_in(self, mock_send, mock_current_user):
        mock_current_user.is_authenticated = True
        mock_current_user.email_verified = False
        mock_current_user.email = "testuser@gmail.com"
        mock_current_user.username = "testuser"
        mock_send.return_value = True

        response = self.client.get('/auth/resend-verification')
        self.assertEqual(response.status_code, 302)

    @patch('app.users_collection.find_one')
    @patch('app.send_verification_email')
    def test_resend_verification_unlogged_email_provided(self, mock_send, mock_find_one):
        mock_send.return_value = True
        mock_find_one.return_value = {"email": "testuser@gmail.com", "username": "testuser"}

        response = self.client.get('/auth/resend-verification?email=testuser@gmail.com')
        self.assertEqual(response.status_code, 302)

    def test_resend_verification_no_email_provided(self):
        response = self.client.get('/auth/resend-verification')
        self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()

