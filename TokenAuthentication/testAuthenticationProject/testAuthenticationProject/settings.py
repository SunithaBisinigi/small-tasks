from pathlib import Path
import os
from datetime import timedelta
# import cloudinary
# import cloudinary.uploader
# import cloudinary.api


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-=ci$be448giou^ld@nofja@u)(loyac&eeu&^c(7o2=c$fcn$#'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

SESSION_COOKIE_SAMESITE = 'Lax'

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework_simplejwt',
    'rest_framework',
    'authenticationApiApp',
    'cloudinary',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'testAuthenticationProject.urls'

# Rest framework......
REST_FRAMEWORK = {
    'DEFAULT_AUTHETICATION_CLASSES':'rest_framework_simplejwt.authentication.JWTAuthentication',
}

#  Password hashing...
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",   
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR,'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'testAuthenticationProject.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# AUTH_USER_MODEL = 'authenticationApiApp.UserToken'
# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')  # Absolute path to the media directory
MEDIA_URL = '/media/'  # Base URL to serve media files


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Simple jwt token settings
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=51),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=100),
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",
    "TOKEN_OBTAIN_SERIALIZER": "rest_framework_simplejwt.serializers.TokenObtainPairSerializer",
    "TOKEN_REFRESH_SERIALIZER": "rest_framework_simplejwt.serializers.TokenRefreshSerializer",
    "TOKEN_VERIFY_SERIALIZER": "rest_framework_simplejwt.serializers.TokenVerifySerializer",
}

         
# cloudinary.config( 
#   cloud_name = "dscxzfeac", 
#   api_key = "424133647694423", 
#   api_secret = "zDWzgHHxbwG77yhjsePtH1paRWs" 
# )
# folder_path = "profile_images/"
# # CLOUDINARY_STORAGE = {
# #     'CLOUD_NAME': 'dscxzfeac',
# #     'API_KEY': '424133647694423',
# #     'API_SECRET': 'zDWzgHHxbwG77yhjsePtH1paRWs',
# # }

# LOGIN_URL = '/api/login/'

# # Use Cloudinary for media storage

# ####### AWS CONFIGURATION
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'

# Amazon S3 settings.
AWS_ACCESS_KEY_ID = 'AKIATG2SAKIBG47YGUKG'
AWS_SECRET_ACCESS_KEY = 'nwZYb4uuCRT5/2FwACd4i6vBpQSabGAkVApndBde'
AWS_STORAGE_BUCKET_NAME = 'django-profile-images'
AWS_S3_REGION_NAME = 'ap-south-1'  # e.g., us-east-1
AWS_S3_CUSTOM_DOMAIN = 'django-profile-images.s3.ap-south-1.amazonaws.com'
