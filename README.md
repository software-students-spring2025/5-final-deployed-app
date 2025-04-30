# MiniShare

![Frontend CI](https://github.com/software-students-spring2025/5-final-deployed-app/actions/workflows/frontend.yml/badge.svg)
![DB Client CI](https://github.com/software-students-spring2025/5-final-deployed-app/actions/workflows/db.yml/badge.svg)

## Project Description
MiniShare is a lightweight content sharing platform designed to let users connect and share moments through a simple, intuitive interface. Built as a containerized microservice application, MiniShare demonstrates modern software engineering practices while providing core social media functionality.

Visit the website here: [MiniShare ](https://mini-share-srm24.ondigitalocean.app/main/)

Key features include:
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
   git clone https://github.com/software-students-spring2025/5-final-deployed-app.git
   cd 5-final-deployed-app
   ```

2. Create a `.env` file in the project root based on the provided `.env.example`:
   ```
   MONGO_URI=mongodb+srv://username:password@cluster.example.mongodb.net/?retryWrites=true&w=majority
   SECRET_KEY=your_secret_key_here

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

## Deployment

### 1. Prepare Your Repository
   - Clone this project to your repository
   - add .env file locally (not pushed) into your root directory

### 2. Connect GitHub to DigitalOcean
   - Go to DigitalOcean App Platform.
   - Click Create App → GitHub Repository → select this repo.
   
### 3. Configure Build Settings
   - Go to DigitalOcean App → Settings → Components→ Commands
   - Manually edit the run command to: python frontend-app/app.py
     
### 4. Set Environment Variables
   - Go to DigitalOcean App → Settings → Environment Variables
   - manually add: MONGO_URI,SECRET_KEY, GOOGLE_CLIENT_ID, and GOOGLE_CLIENT_SECRET (which are provide by .env)


   
### 5. Deploy the App
  - Save settings.
  - Click Deploy.
  - Wait for build → deployment → health checks → Success.
  - Then you can visit the website via the link generate by DigitalOcean

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

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
