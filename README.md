# MiniShare

![Frontend CI](https://github.com/software-students-spring2025/5-final-deployed-app/actions/workflows/frontend.yml/badge.svg)
![DB Client CI](https://github.com/software-students-spring2025/5-final-deployed-app/actions/workflows/db.yml/badge.svg)

## Project Description
MiniShare is a lightweight content sharing platform designed to let users connect and share moments through a simple, intuitive interface. Built as a containerized microservice application, MiniShare demonstrates modern software engineering practices while providing core social media functionality.

Key features include:
- User registration with email verification system
- Google OAuth integration for simplified login
- Image sharing with captions
- User profiles with customizable bios
- Follow/unfollow functionality to connect with other users
- Comment system for engagement
- Responsive UI that works on both desktop and mobile devices

## Architecture

MiniShare is composed of two main microservices:

1. **Web Application (`frontend-app`)**: A Flask-based web application that handles user interface, authentication, and business logic
2. **Database Service (`db`)**: A MongoDB database service that provides data persistence

Both services are containerized and can be deployed independently.

## Team members

- [Polaris Wu](https://github.com/Polaris-Wu450)
- [Elena Li](https://github.com/HuixinLi-Elena)
- [Michael Liu](https://github.com/Michaelliu1017)
- [Eric Xu](https://github.com/EricXu1244)

## Setup Instructions

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)
- MongoDB Atlas account (for database hosting)

### Environment Configuration

1. Clone the repository:
   ```
   git clone https://github.com/your-organization/minishare.git
   cd minishare
   ```

2. Create a `.env` file in the project root based on the provided `.env.example`:
   ```
   MONGO_URI=mongodb+srv://username:password@cluster.example.mongodb.net/?retryWrites=true&w=majority
   SECRET_KEY=your_secret_key_here

   # Gmail settings (for sending verification emails)
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password  
   MAIL_DEFAULT_SENDER=your-email@gmail.com

   # Google OAuth settings (for "Sign in with Google")
   GOOGLE_CLIENT_ID=your_google_client_id_here
   GOOGLE_CLIENT_SECRET=your_google_client_secret_here

   # DEVELOPMENT or PRODUCTION: set to 'True' for debug logging locally, 'False' on servers
   DEBUG=True
   ```

3. Set up MongoDB Atlas:
   - Create a MongoDB Atlas account if you don't have one
   - Create a new cluster
   - In the cluster, create a database named `project5_db` with collections:
     - `userInfo`
     - `posts`
     - `comments`
     - `follows`
   - Create a database user with read/write access
   - Get your connection string and update the `MONGO_URI` in your `.env` file

4. Set up Google OAuth:
   - Go to the [Google Developer Console](https://console.developers.google.com/)
   - Create a new project
   - Enable the Google+ API and Google OAuth API
   - Create OAuth consent screen (External)
   - Create OAuth credentials (Web application)
   - Add authorized redirect URIs:
     - `http://127.0.0.1:8080/auth/login/google/callback`
     - `http://localhost:8080/auth/login/google/callback`
   - Get your client ID and client secret and update the `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in your `.env` file

5. Set up Gmail for email sending:
   - Create an App Password for your Gmail account ([instructions](https://support.google.com/accounts/answer/185833))
   - Update the `MAIL_USERNAME`, `MAIL_PASSWORD`, and `MAIL_DEFAULT_SENDER` in your `.env` file

### Running the Application

1. Build and start the services using Docker Compose:
   ```
   docker-compose up --build
   ```

2. Access the application at `http://localhost:8080`

### Development Setup

If you want to run the application directly on your machine for development:

1. Create a Python virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the Flask application:
   ```
   cd frontend-app
   python app.py
   ```

## API Documentation

The MiniShare application provides the following RESTful API endpoints:

### Authentication

- **POST** `/auth/register`: Register a new user
- **POST** `/auth/login`: Log in an existing user
- **GET** `/auth/logout`: Log out the current user
- **GET** `/auth/login/google`: Initiate Google OAuth login
- **GET** `/auth/verify-email/<token>`: Verify user email with token

### User Management

- **GET** `/main/profile/<username>`: View a user's profile
- **POST** `/main/edit-profile`: Edit the current user's profile
- **POST** `/main/follow/<username>`: Follow a user
- **POST** `/main/unfollow/<username>`: Unfollow a user
- **GET** `/main/profile/<username>/followers`: View a user's followers
- **GET** `/main/profile/<username>/following`: View users that a user is following

### Content Management

- **GET** `/main/feed`: View recent posts
- **GET** `/main/create-post`: View post creation form
- **POST** `/main/create-post`: Create a new post
- **POST** `/main/post/<post_id>/comment`: Add a comment to a post
- **POST** `/main/post/<post_id>/delete`: Delete a post

## Testing

### DB Service Tests
```
cd db
pytest
```

### Frontend Service Tests
```
cd frontend-app
pytest
```

## Coverage Reports

### DB Module
```
pytest db --cov=db --cov-report=term-missing
```

### Frontend Module
```
cd frontend-app
pytest --cov=. --cov-report=term-missing
```

## Deployment

*Deployment instructions will be added once CI/CD pipelines are implemented.*

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
