# from django.shortcuts import render, redirect
# from django.contrib.auth import login, authenticate
# from rest_framework.authtoken.models import Token
# from django.contrib.auth.models import User
# from .forms import RegistrationForm, LoginForm
# from .models import UserToken,User
# from django.shortcuts import render, redirect
# from rest_framework.authtoken.models import Token
# from django.contrib.auth.models import User  # Import the default User model
# from .forms import RegistrationForm, LoginForm
# from django.contrib.auth.decorators import login_required
# from django.contrib import messages
# import logging
# from django.views.decorators.csrf import csrf_exempt
# from rest_framework_simplejwt.tokens import RefreshToken

# __name__ = "application.views"
# logger = logging.getLogger(__name__)

# # -------------------token generation.......
# # def get_tokens_for_user(user):
# #     refresh = RefreshToken.for_user(user)
# #     return {
# #         'refresh': str(refresh),
# #         'access': str(refresh.access_token),
# #     }

# # ------------Registration---------------
# # def registration(request):
# #     if request.method == 'POST':
# #         form = RegistrationForm(request.POST)
# #         if form.is_valid():
# #             username = form.cleaned_data['username']
# #             email = form.cleaned_data['email']
# #             password1 = form.cleaned_data['password1']
# #             password2 = form.cleaned_data['password2']
# #             if User.objects.filter(email=email).exists():
# #                 messages.error(request, 'Email already exists. Please use a different email.')
# #                 return redirect('registration')  # Redirect to the registration page
            
# #             user = User.objects.create_user(username=username, email=email, password=password1)

# #             # Generate tokens and save them in the Token model
# #             tokens = get_tokens_for_user(user)
# #             access_token = tokens['access']
# #             refresh_token =  tokens['refresh']
# #             custom_token, created = UserToken.objects.get_or_create(user=user)
# #             custom_token.access_token = access_token
# #             custom_token.refresh_token = refresh_token
# #             custom_token.save()

# #             user = authenticate(request, username=username, password=password1)

# #             # Check if the access token is valid and redirect the user
# #             if request.user.auth_token:
# #                 return redirect('home')

# #             messages.success(request, 'Registration successful')
# #             return redirect('home')

# #         else:
# #             messages.error(request, 'Invalid form data')
# #     else:
# #         form = RegistrationForm()

# #     return render(request, 'registration.html', {'form': form})
# # ============11:25 changes......this working upto data stored in db. but not authentication========================
from datetime import timedelta
# import logging
# from django.contrib.auth import authenticate, login
# from django.contrib.auth.models import User
# from django.shortcuts import render, redirect
from django.contrib import messages
# from rest_framework.authtoken.models import Token
# from .models import UserToken
# from django.http import JsonResponse
from django.utils import timezone

# def registration(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             email = form.cleaned_data['email']
#             password1 = form.cleaned_data['password1']
#             password2 = form.cleaned_data['password2']

#             # Check if the email already exists
#             if User.objects.filter(email=email).exists():
#                 messages.error(request, 'Email already exists. Please use a different email.')
#                 return redirect('registration')  # Redirect to the registration page

#             # Create a new user
#             user = User.objects.create_user(username=username, email=email, password=password1)

#             # Generate tokens and save them in the Token model
#             access_token, refresh_token = get_tokens_for_user(request, user)

#             # Log in the user using the access token
#             user = authenticate(request, username=username, password=password1)
#             if user is not None:
#                 login(request, user)
#                 messages.success(request, 'Registration successful')
#                 return redirect('home')
#             else:
#                 messages.error(request, 'Failed to authenticate user.')

#         else:
#             messages.error(request, 'Invalid form data')
#     else:
#         form = RegistrationForm()

#     return render(request, 'registration.html', {'form': form})

# def get_tokens_for_user(request, user):
#     # Generate access token
#     tokens, created = Token.objects.get_or_create(user=user)
#     refresh = RefreshToken.for_user(user)
#     access_token = refresh.access_token
#     print("tokens.......", tokens)
#     print("access ........",access_token)
#     print("refresh......",refresh)
#     # You should implement your logic to generate or retrieve the refresh token as needed
#     # refresh_token = "your_refresh_token_generation_logic_here"

#     # Check if the access token is expired
#     if tokens.created < timezone.now() - timedelta(minutes=30):
#         messages.error(request, 'Your access token has expired. Please log in again.')
#         return redirect('login_view')  # Redirect to the login page

#     # Create or update the custom UserToken model for the user
#     custom_token, created = UserToken.objects.get_or_create(user=user)
#     custom_token.access_token = access_token
#     custom_token.refresh_token = refresh
#     custom_token.save()

#     return access_token, refresh

# # --------------login------------------------
# # def login_view(request):
# #     if request.method == 'POST':
# #         form = LoginForm(request.POST)
# #         if form.is_valid():
# #             username = form.cleaned_data['username']
# #             password = form.cleaned_data['password']
# #             user = authenticate(request, username=username, password=password)
# #             if user:
# #                 login(request, user)
# #                 Token.objects.get_or_create(user=user)
# #                 return redirect('home')
# #     else:
# #         form = LoginForm()
# #     return render(request, 'login.html', {'form': form})

# from django.contrib.auth import authenticate, login
# from rest_framework.authtoken.models import Token
# from django.shortcuts import render, redirect
# from .forms import LoginForm  # Import your LoginForm or authentication form here
# from .models import UserToken  # Import your UserToken model here
# from django.views.decorators.http import require_POST
# # def login_view(request):
# #     if request.method == 'POST':
# #         form = LoginForm(request.POST)
# #         if form.is_valid():
# #             username = form.cleaned_data['username']
# #             password = form.cleaned_data['password']

# #             # Authenticate the user
# #             # user_token, created = UserToken.objects.get_or_create(user=request.user)
# #             # access_token = user_token.access_token
# #             user = authenticate(request, username=username, password=password)
            
# #             if user:
# #                 # Check if the access token is valid
# #                 user_token, created = UserToken.objects.get_or_create(user=user)
# #                 access_token = user_token.access_token
# #                 if access_token:
# #                     # Log in the user using the access token
# #                     login(request, user)
# #                     token, created = Token.objects.get_or_create(user=user)
# #                     user = authenticate(request, username=username, access_token=access_token)
# #                     if user:
# #                         login(request, user)
# #                         Token.objects.get_or_create(user=user)
# #                         return redirect('home')
# #                 else:
# #                     # Access token is missing or invalid
# #                     messages.error(request, 'Invalid access token. Please log in again.')
# #                     return redirect('login')
# #             else:
# #                 # Authentication failed
# #                 messages.error(request, 'Failed to authenticate user.')
# #                 return redirect('login')
# #         else:
# #             messages.error(request, 'Invalid form data')
# #     else:
# #         form = LoginForm()
    
# #     return render(request, 'login.html', {'form': form})
# # =========the above login not sending accesstoken to js in json formate ===============================
# # @require_POST
# logger = logging.getLogger(__name__)
# def login_view(request):
#     logger.debug(f"Request method: {request.method}")
#     print(request.method)

#     if request.method == 'POST':
#         form = LoginForm(request.POST)
#         print(".................1.............")
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             password = form.cleaned_data['password']

#             user = authenticate(request, username=username, password=password)
#             print(".................2.............")
#             if user:
#                 user_token, created = UserToken.objects.get_or_create(user=user)
#                 access_token = user_token.access_token
#                 print(".................3.............")
#                 if access_token:
#                     login(request, user)

#                     token, created = Token.objects.get_or_create(user=user)
                    
#                     response_data = {
#                         'access_token': str(token),
#                         'message': 'Login successful',
#                     }
#                     print(".................4.............")
#                     return JsonResponse(response_data)
#                 else:
#                     response_data = {
#                         'message': 'Invalid access token. Please log in again.',
#                     }
#                     print(".................5.............")
#                     return JsonResponse(response_data, status=401)
#             else:
#                 response_data = {
#                     'message': 'Failed to authenticate user.',
#                 }
#                 print(".................6.............")
#                 return JsonResponse(response_data, status=401)
#         else:
#             response_data = {
#                 'message': 'Invalid form data.',
#             }
#             print(".................7.............")
#             return JsonResponse(response_data, status=400)
#     else:
#         form = LoginForm()
#         response_data = {
#             'message': 'GET request not allowed for login.',
#         }
#         print(".................8.............")
#         return JsonResponse(response_data, status=405)

# # --------------home---------------------
# @login_required
# def home(request):
#     # Check if the user's access token is still valid
#     if request.user.auth_token:
#         access_token = request.user.auth_token.key
#         return render(request, 'home.html', {'access_token': access_token})
#     else:
#         messages.error(request, 'Access token expired. Please log in again.')
#         return redirect('login')  # Redirect to the login page

# #

# # =================================token implememtation......====================================
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .forms import RegistrationForm, LoginForm
from .models import UserToken
import logging
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from django.http import JsonResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, permission_classes


__name__ = "application.views"
logger = logging.getLogger(__name__)

# token generation.......
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@csrf_exempt  # Disable CSRF protection for this view
# def registration(request):
#     if request.method == 'POST':
#         username = request.POST.get('username')
#         email = request.POST.get('email')
#         password = request.POST.get('password')

#         if User.objects.filter(email=email).exists():
#             # Email already exists
#             return JsonResponse({'error': 'Email already exists. Please use a different email.'}, status=400)
#         else:
#             user = User.objects.create_user(username=username, email=email, password=password)
#             login(request, user)

#             token, created = UserToken.objects.get_or_create(user=user)
#             access_token = token.key

#             return JsonResponse({'message': 'Registration successful', 'access_token': access_token})

#     return render(request, 'registration.html')
def registration(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']

            # Check if the email already exists
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists. Please use a different email.')
                return redirect('registration')  # Redirect to the registration page

            # Create a new user
            user = User.objects.create_user(username=username, email=email, password=password1)

            # Generate tokens and save them in the Token model
            access_token, refresh_token = get_tokens_for_user(request, user)

            # Log in the user using the access token
            user = authenticate(request, username=username, password=password1)
            if user is not None:
                login(request, user)
                access_token_dict ={
                    'access_token':access_token,
                }
                messages.success(request, 'Registration successful')
                return redirect('home')
            else:
                messages.error(request, 'Failed to authenticate user.')

        else:
            messages.error(request, 'Invalid form data')
    else:
        form = RegistrationForm()

    return render(request, 'registration.html', {'form': form})

def get_tokens_for_user(request, user):
    # Generate access token
    tokens, created = Token.objects.get_or_create(user=user)
    refresh = RefreshToken.for_user(user)
    access_token = refresh.access_token
    print("tokens.......", tokens)
    print("access ........",access_token)
    print("refresh......",refresh)
    # You should implement your logic to generate or retrieve the refresh token as needed
    # refresh_token = "your_refresh_token_generation_logic_here"

    # Check if the access token is expired
    if tokens.created < timezone.now() - timedelta(minutes=30):
        messages.error(request, 'Your access token has expired. Please log in again.')
        return redirect('login_view')  # Redirect to the login page

    # Create or update the custom UserToken model for the user
    custom_token, created = UserToken.objects.get_or_create(user=user)
    custom_token.access_token = access_token
    custom_token.refresh_token = refresh
    custom_token.save()

    return access_token, refresh
@csrf_exempt  # Disable CSRF protection for this view
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                try:
                    token = UserToken.objects.get(user=user)
                    access_token = token.access_token
                except Token.DoesNotExist:
                    access_token = None
                
                if access_token:
                    # Return a JSON response with success message and access token
                    return JsonResponse({'message': 'Login successful', 'access_token': access_token})
                else:
                    # Return a JSON response with an error message if the access token is not found
                    return JsonResponse({'error': 'Access token not found'}, status=400)
            else:
                # Return a JSON response with an error message
                return JsonResponse({'error': 'Invalid username or password'}, status=400)
        else:
            # Return a JSON response with form errors
            return JsonResponse({'error': 'Invalid form data', 'form_errors': form.errors}, status=400)
    else:
        form = LoginForm()
        return render(request, 'login.html', {'form': form, 'error_message': 'Invalid username or password'})

def home(request):
    if request.user.is_authenticated:
        return render(request, 'home.html')
    else:
        return redirect('login')


from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework.views import APIView

class UserDetailsView(APIView):
    @authentication_classes([TokenAuthentication])  # Use the appropriate authentication method
    @permission_classes([IsAuthenticated])
    def get(self, request):
        user = request.user
        user_data = {
            'username': user.username,
            'email': user.email,
            # Add more user details as needed
        }
        return Response(user_data)
