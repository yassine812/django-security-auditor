"""Vulnerable Django settings fixture (intentionally insecure for tests)."""
import os

SECRET_KEY = "insecure-hardcoded-secret-key-abc123xyz789"

DEBUG = True

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "docsapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # NOTE: CsrfViewMiddleware intentionally missing (test fixture)
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "vulnproj.urls"
WSGI_APPLICATION = "vulnproj.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "docs",
        "USER": "docs_admin",
        "PASSWORD": "supersecretpassword123",
        "HOST": "db.internal",
        "PORT": "5432",
    }
}

SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
SECURE_SSL_REDIRECT = False
SECURE_HSTS_SECONDS = 0
SECURE_CONTENT_TYPE_NOSNIFF = False
X_FRAME_OPTIONS = "ALLOW"
SECURE_REFERRER_POLICY = "unsafe-url"
SESSION_COOKIE_AGE = 99999999
AUTH_PASSWORD_VALIDATORS = []

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": [],
}

CORS_ALLOW_ALL_ORIGINS = True

STATIC_URL = "/static/"
