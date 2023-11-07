from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from .forms import RegistrationForm, LoginForm
from .models import UserToken,User
from django.shortcuts import render, redirect
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User  # Import the default User model
from .forms import RegistrationForm, LoginForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
import logging
from django.views.decorators.csrf import csrf_exempt
from rest_framework_simplejwt.tokens import RefreshToken

__name__ = "application.views"
logger = logging.getLogger(__name__)

# -------------------token generation.......
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# ------------Registration---------------
def registration(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            password1 = form.cleaned_data['password1']
            password2 = form.cleaned_data['password2']
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists. Please use a different email.')
                return redirect('registration')  # Redirect to the registration page
            
            user = User.objects.create_user(username=username, email=email, password=password1)

            # Generate tokens and save them in the Token model
            tokens = get_tokens_for_user(user)
            access_token = tokens['access']
            refresh_token =  tokens['refresh']
            custom_token, created = UserToken.objects.get_or_create(user=user)
            custom_token.access_token = access_token
            custom_token.refresh_token = refresh_token
            custom_token.save()
            
            # Check if the access token is valid and redirect the user
            if request.user.auth_token:
                return redirect('home')

            messages.success(request, 'Registration successful')
            return redirect('home')

        else:
            messages.error(request, 'Invalid form data')
    else:
        form = RegistrationForm()

    return render(request, 'registration.html', {'form': form})

# --------------login------------------------
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                Token.objects.get_or_create(user=user)
                return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


# --------------home---------------------
@login_required
def home(request):
    # Check if the user's access token is still valid
    if request.user.auth_token:
        access_token = request.user.auth_token.key
        return render(request, 'home.html', {'access_token': access_token})
    else:
        messages.error(request, 'Access token expired. Please log in again.')
        return redirect('login')  # Redirect to the login page















# from django.shortcuts import render, redirect
# from django.contrib.auth import login, authenticate
# from rest_framework.authtoken.models import Token
# from django.contrib.auth.models import User
# from .forms import RegistrationForm, LoginForm
# from .models import Token,CustomUser 
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

# # token generation.......
# def get_tokens_for_user(user):
#     refresh = RefreshToken.for_user(user)
#     return {
#         'refresh': str(refresh),
#         'access': str(refresh.access_token),
#     }


#     # Save the tokens to the database
#     Token.objects.create(user=user, access_token=access_token, refresh_token=refresh_token)

# # @csrf_exempt
# def registration(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             email = form.cleaned_data['email']
#             password = form.cleaned_data['password']

#             if User.objects.filter(email=email).exists():
#                 return JsonResponse({'error': 'Email already exists. Please use a different email.'}, status=400)
#             else:
#                 user = User.objects.create_user(username=username, email=email, password=password)

#                 # Generate tokens and save them in the Token model
#                 tokens = get_tokens_for_user(user)
#                 Token.objects.create(user=user, access_token=tokens['access'], refresh_token=tokens['refresh'])

#                 # Check if the access token is valid and redirect the user
#                 if request.user.auth_token:
#                     return redirect('home')

#                 return JsonResponse({'message': 'Registration successful', 'access_token': tokens['access']})
#         else:
#             return JsonResponse({'error': 'Invalid form data', 'form_errors': form.errors}, status=400)
#     else:
#         form = RegistrationForm()

#     return render(request, 'registration.html', {'form': form})
# def login_view(request):
#     if request.method == 'POST':
#         form = LoginForm(request.POST)
#         if form.is_valid():
#             username = form.cleaned_data['username']
#             password = form.cleaned_data['password']
#             user = authenticate(request, username=username, password=password)
#             if user:
#                 login(request, user)
#                 Token.objects.get_or_create(user=user)
#                 return redirect('home')
#     else:
#         form = LoginForm()
#     return render(request, 'login.html', {'form': form})

# @login_required
# def home(request):
#     # Check if the user's access token is still valid
#     if request.user.auth_token:
#         access_token = request.user.auth_token.key
#         return JsonResponse({'message': 'Welcome to the home page', 'access_token': access_token})
#     else:
#         return JsonResponse({'error': 'Access token expired. Please log in again.'}, status=401)

# # =================================token implememtation......====================================
# # from django.shortcuts import render, redirect
# # from django.contrib.auth import login, authenticate
# # from rest_framework.authtoken.models import Token
# # from django.contrib.auth.models import User
# # from .forms import RegistrationForm, LoginForm
# # from .models import Token,CustomUser
# # import logging
# # from rest_framework_simplejwt.tokens import RefreshToken
# # from django.views.decorators.csrf import csrf_exempt
# # from rest_framework.decorators import api_view
# from django.http import JsonResponse
# # from rest_framework.permissions import IsAuthenticated
# # from rest_framework.decorators import api_view, permission_classes


# # __name__ = "application.views"
# # logger = logging.getLogger(__name__)

# # # token generation.......
# # def get_tokens_for_user(user):
# #     refresh = RefreshToken.for_user(user)
# #     return {
# #         'refresh': str(refresh),
# #         'access': str(refresh.access_token),
# #     }

# # @csrf_exempt  # Disable CSRF protection for this view
# # def registration(request):
# #     if request.method == 'POST':
# #         username = request.POST.get('username')
# #         email = request.POST.get('email')
# #         password = request.POST.get('password')

# #         if User.objects.filter(email=email).exists():
# #             # Email already exists
# #             return JsonResponse({'error': 'Email already exists. Please use a different email.'}, status=400)
# #         else:
# #             user = User.objects.create_user(username=username, email=email, password=password)
# #             login(request, user)

# #             token, created = Token.objects.get_or_create(user=user)
# #             access_token = token.key

# #             return JsonResponse({'message': 'Registration successful', 'access_token': access_token})

# #     return render(request, 'registration.html')
# # @csrf_exempt  # Disable CSRF protection for this view
# # def login_view(request):
# #     if request.method == 'POST':
# #         form = LoginForm(request.POST)
# #         if form.is_valid():
# #             username = form.cleaned_data['username']
# #             password = form.cleaned_data['password']
# #             user = authenticate(request, username=username, password=password)
# #             if user:
# #                 login(request, user)
# #                 try:
# #                     token = Token.objects.get(user=user)
# #                     access_token = token.access_token
# #                 except Token.DoesNotExist:
# #                     access_token = None
                
# #                 if access_token:
# #                     # Return a JSON response with success message and access token
# #                     return JsonResponse({'message': 'Login successful', 'access_token': access_token})
# #                 else:
# #                     # Return a JSON response with an error message if the access token is not found
# #                     return JsonResponse({'error': 'Access token not found'}, status=400)
# #             else:
# #                 # Return a JSON response with an error message
# #                 return JsonResponse({'error': 'Invalid username or password'}, status=400)
# #         else:
# #             # Return a JSON response with form errors
# #             return JsonResponse({'error': 'Invalid form data', 'form_errors': form.errors}, status=400)
# #     else:
# #         form = LoginForm()
# #         return render(request, 'login.html', {'form': form, 'error_message': 'Invalid username or password'})

# # def home(request):
# #     if request.user.is_authenticated:
# #         return render(request, 'home.html')
# #     else:
# #         return redirect('login')

# # @api_view(['GET'])
# # @permission_classes([IsAuthenticated])
# def get_user_details(request):
#     user = request.user
#     # You can customize the data you want to return here based on your User model.
#     user_data = {
#         'username': user.username,
#         'email': user.email,
#         # Add more fields as needed
#     }
#     return JsonResponse(user_data)