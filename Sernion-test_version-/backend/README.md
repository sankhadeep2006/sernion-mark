# Sernion Mark Backend

A robust Django REST API backend for the Sernion Mark multimedia annotation platform.

## 🖥️ Windows Backend Development Guide (Recommended)

This section focuses on setting up and running the backend on Windows.

### System Requirements

- Python 3.10.x recommended (supports 3.8 – 3.12)
- pip (bundled with Python)
- Git for Windows
- Optional: Redis (for Celery), PostgreSQL (for production)

### Check Your Python on Windows

Run one of the following in Command Prompt (cmd) or PowerShell:

```bash
python --version
py -V
```

If you have multiple Python versions installed, prefer the `py` launcher:

```bash
py -3.10 --version
```

### Create and Activate Virtual Environment

Command Prompt (cmd):
```bash
cd backend
py -3.10 -m venv venv
venv\Scripts\activate
```

PowerShell:
```bash
cd backend
py -3.10 -m venv venv
./venv/Scripts/Activate.ps1
```

If PowerShell blocks activation, run as a one-time setup:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Note for Windows:
- If you encounter issues with `python-magic`, install the Windows wheel: `pip install python-magic-bin==0.4.14`.
- Keep `psycopg2-binary` for Windows; do not switch to `psycopg2` unless you have build tools.

### Environment Variables (.env)

Use the provided `test.env` as a template:
```bash
copy test.env .env
```
Then edit `.env` with your values (see Environment Variables section below).

### Database and Migrations
```bash
python manage.py makemigrations
python manage.py migrate
```

### Create Superuser
```bash
python manage.py createsuperuser
```

### Run Server
```bash
python manage.py runserver
```

Browse: `http://localhost:8000`

### Recommended IDEs and Extensions

- Visual Studio Code (lightweight, free)
  - Extensions: "Python" (Microsoft), "Pylance", "Black Formatter", "isort", "Django"
  - Optional: "dotenv" or "Env" for .env syntax highlighting
- PyCharm Community/Professional (Django support is best in Professional)

VS Code Debugging (optional): create `.vscode/launch.json` and use Django configuration; ensure your venv Python is selected.

---

## 📦 Dependencies and Versions

Key runtime dependencies (see `requirements.txt` for full list):

- Django 4.2.7
- Django REST Framework 3.14.0
- django-cors-headers 4.3.1
- djangorestframework-simplejwt 5.3.0
- Pillow 10.1.0
- drf-yasg 1.21.7 (API docs)
- python-dotenv 1.0.0 and django-environ 0.11.2 (env management)
- Celery 5.3.4 and redis 5.0.1 (async tasks; optional in dev)
- psycopg2-binary 2.9.9 (PostgreSQL; use in prod)

Optional services:
- Redis (required if you run Celery workers)
- PostgreSQL (recommended for staging/production)

---

## 🧰 Windows Troubleshooting

- Module build/compile errors
  - Ensure you are using `psycopg2-binary` on Windows.
  - If `python-magic` fails, install `python-magic-bin==0.4.14`.
- Virtualenv activation blocked in PowerShell
  - Run PowerShell as user and execute: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
- Port already in use (8000)
  - Use a different port: `python manage.py runserver 8001`.
- Environment variables not loaded
  - Verify `.env` exists in `backend/` and that `python-dotenv`/`django-environ` are configured in `settings.py`.

---

## 🏗️ Architecture Overview

Based on the system architecture diagram, this backend provides:

- **REST API** for frontend communication
- **Authentication & Authorization** with JWT tokens
- **Data Storage** for users, projects, and annotations
- **File Management** for multimedia uploads
- **AI Integration** ready for auto-labeling features

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Installation

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   ```bash
   # Create .env file from template
   # Windows (cmd)
   copy test.env .env
   # macOS/Linux
   cp test.env .env
   # Edit .env with your configuration
   ```

5. **Run database migrations:**
   ```bash
   python manage.py makemigrations
   python manage.py migrate
   ```

6. **Create superuser:**
   ```bash
   python manage.py createsuperuser
   ```

7. **Start the development server:**
   ```bash
   python manage.py runserver
   ```

The API will be available at `http://localhost:8000`

## 📁 Project Structure

```
backend/
├── sernion_mark/              # Main Django project
│   ├── __init__.py
│   ├── settings.py            # Django settings
│   ├── urls.py               # Main URL configuration
│   └── wsgi.py               # WSGI configuration
├── authentication/            # Authentication app
│   ├── models.py             # User and profile models
│   ├── serializers.py        # API serializers
│   ├── views.py              # API views
│   ├── urls.py               # Authentication URLs
│   └── admin.py              # Django admin
├── projects/                 # Projects app
│   ├── models.py             # Project and dataset models
│   └── urls.py               # Project URLs
├── annotations/              # Annotations app
│   └── urls.py               # Annotation URLs
├── manage.py                 # Django management script
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

## 🔐 Authentication API

### Registration
```http
POST /api/v1/auth/register/
Content-Type: application/json

{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "securepassword123",
  "password_confirm": "securepassword123",
  "full_name": "John Doe"
}
```

### Login
```http
POST /api/v1/auth/login/
Content-Type: application/json

{
  "username": "johndoe",
  "password": "securepassword123"
}
```

### Response Format
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": 1,
    "username": "johndoe",
    "email": "john@example.com",
    "full_name": "John Doe",
    "is_verified": false
  },
  "tokens": {
    "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  }
}
```

## 🔗 Frontend Integration

### JavaScript API Client

The frontend includes a JavaScript API client (`frontend/js/api.js`) that handles:

- Authentication token management
- Automatic token refresh
- API request/response handling
- Error handling

### Usage Example

```javascript
// Initialize API client
const api = new SernionMarkAPI('http://localhost:8000/api/v1');

// Login
const response = await api.login({
    username: 'johndoe',
    password: 'password123'
});

if (response.success) {
    console.log('Logged in:', response.user);
    // Tokens are automatically stored
}

// Make authenticated requests
const profile = await api.getProfile();
```

### Form Integration

The API client automatically integrates with your existing HTML forms:

```html
<!-- Login form -->
<form id="loginForm">
    <input name="username" type="text" required>
    <input name="password" type="password" required>
    <button type="submit">Login</button>
</form>

<!-- Signup form -->
<form id="signupForm">
    <input name="username" type="text" required>
    <input name="email" type="email" required>
    <input name="password" type="password" required>
    <input name="password_confirm" type="password" required>
    <input name="full_name" type="text" required>
    <button type="submit">Sign Up</button>
</form>
```

## 📊 Database Models

### User Model
- Extended Django User with additional fields
- Phone number, bio, avatar support
- Account verification and security features
- Login attempt tracking and account lockout

### Project Model
- Support for audio, video, image, and text projects
- Collaboration features
- Project status management
- Public/private project settings

### Dataset Model
- File management for multimedia content
- Metadata storage
- Processing status tracking

### Annotation Model
- Flexible annotation content storage (JSON)
- Multiple annotation types
- Verification system
- Confidence scoring

## 🛡️ Security Features

### Authentication
- JWT-based authentication
- Token refresh mechanism
- Token blacklisting for secure logout
- Account lockout after failed attempts

### Password Security
- Strong password validation
- Secure password hashing
- Password reset functionality
- Email-based verification

### API Security
- CORS protection
- Rate limiting
- Input validation
- SQL injection protection

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
# Django Configuration
SECRET_KEY=your-secret-key-here
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DATABASE_URL=sqlite:///db.sqlite3

# Email Configuration
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password

# Frontend URL
FRONTEND_URL=http://localhost:5500
```

## 🧪 Testing

### Run Tests
```bash
python manage.py test
```

### Test Specific App
```bash
python manage.py test authentication
python manage.py test projects
```

## 📚 API Documentation

### Swagger UI
Visit `http://localhost:8000/api/docs/` for interactive API documentation.

### Available Endpoints

#### Authentication
- `POST /api/v1/auth/register/` - User registration
- `POST /api/v1/auth/login/` - User login
- `POST /api/v1/auth/logout/` - User logout
- `GET /api/v1/auth/verify/` - Token verification

#### User Profile
- `GET /api/v1/user/profile/` - Get user profile
- `PUT /api/v1/user/profile/` - Update user profile
- `POST /api/v1/user/change-password/` - Change password

#### Password Reset
- `POST /api/v1/auth/password-reset/` - Request password reset
- `POST /api/v1/auth/password-reset/confirm/` - Confirm password reset

#### JWT Tokens
- `POST /api/token/refresh/` - Refresh access token
- `POST /api/token/blacklist/` - Blacklist refresh token

## 🚀 Deployment

### Production Settings

1. **Update settings.py:**
   ```python
   DEBUG = False
   ALLOWED_HOSTS = ['your-domain.com']
   ```

2. **Use production database:**
   ```python
   DATABASES = {
       'default': {
           'ENGINE': 'django.db.backends.postgresql',
           'NAME': 'your_db_name',
           'USER': 'your_db_user',
           'PASSWORD': 'your_db_password',
           'HOST': 'localhost',
           'PORT': '5432',
       }
   }
   ```

3. **Configure static files:**
   ```bash
   python manage.py collectstatic
   ```

4. **Use production WSGI server:**
   ```bash
   pip install gunicorn
   gunicorn sernion_mark.wsgi:application
   ```

## 🔄 Database Migrations

### Create Migrations
```bash
python manage.py makemigrations
```

### Apply Migrations
```bash
python manage.py migrate
```

### Reset Database
```bash
python manage.py flush
```

## 📝 Admin Interface

Access the Django admin at `http://localhost:8000/admin/`

Features:
- User management
- Project oversight
- Annotation monitoring
- System statistics

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is part of the Sernion Mark multimedia annotation platform.

## 🆘 Support

For issues and questions:
1. Check the API documentation
2. Review the logs in `logs/django.log`
3. Check the Django admin interface
4. Create an issue in the repository

## 🔮 Future Enhancements

- [ ] Real-time collaboration features
- [ ] Advanced file processing
- [ ] AI integration for auto-labeling
- [ ] Export functionality
- [ ] Advanced analytics
- [ ] Mobile API support
