# # =================================token implememtation......====================================
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .forms import RegistrationForm, LoginForm, UserProfileForm
from .models import UserToken, UserProfile
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from rest_framework.permissions import IsAuthenticated
from django.contrib import messages
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.authentication import JWTAuthentication
from calendar import timegm
from datetime import datetime
import json
from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.auth.decorators import login_required
from rest_framework_simplejwt.exceptions import InvalidToken
import base64
from jwt import decode as jwt_decode
from datetime import datetime, timezone
from django.contrib.auth import authenticate, login
from rest_framework.decorators import permission_classes
from django.views.decorators.cache import never_cache


######################################## DECODING THE TOKEN #####################################
def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

############################ TOKEN GENERATION ######################################
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# ############################# REGISTRATION ##############################
@csrf_exempt
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
                return redirect('registration')  
            
            user = User.objects.create_user(username=username, email=email, password=password1)
            login(request, user)
            tokens = get_tokens_for_user(user)
            access_token = tokens['access']
            
            # Save the access token in your UserToken model
            custom_token, created = UserToken.objects.get_or_create(user=user)
            custom_token.access_token = access_token
            custom_token.refresh_token = tokens['refresh']
            custom_token.save()
            
            # Prepare the access token for sending to the frontend
            access_token_dict = {
                'access_token': access_token,
            }
            
            # Return the access token to the frontend
            response = JsonResponse(access_token_dict)
            
            # Store the access token in a cookie
            response.set_cookie('access_token', access_token, max_age=3600*3, httponly=True, samesite='Lax',  path='/')  # Adjust the max_age as needed
            
            return response

    # If the request is not a POST or form validation fails, render the registration form
    form = RegistrationForm()
    return render(request, 'registration.html', {'form': form})

##################################  LOGIN  ########################################
@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        print("sunitha--------------------",data)
        email = data['email']
        password = data['password']
        db_user = User.objects.get(email = email)
        print("----------------------------dbuser----------------",db_user)
        user = authenticate(request, username=db_user, password=password)
        print("getting user object................................................", user)
        if user is not None:
            login(request, user)
            try:
                user_token, created = UserToken.objects.get_or_create(user=user)
                # refresh = RefreshToken(user_token.refresh_token)
                access_token = user_token.access_token

                # Check if the access token is expired
                decoded_token = jwt_decode(access_token, options={"verify_signature": False})
                expiration_time = decoded_token.get('exp')
                current_time = datetime.now(timezone.utc).timestamp()
                
                if expiration_time and current_time > expiration_time:
                    # Token is expired, refresh it
                    refresh_token = RefreshToken(user_token.refresh_token)
                    new_access_token = str(refresh_token.access_token)
                    user_token.access_token = new_access_token
                    user_token.save()
                    access_token = new_access_token

                print("line----------------131")
            except UserToken.DoesNotExist:
                access_token = None
            print("access token------------------",type(access_token))
            if access_token :
                print("line----------------137")
                response = JsonResponse({'message': 'Login successful'})
                response.set_cookie('access_token', access_token, max_age=3600*3, httponly=True, samesite='Lax', path='/')  # httponly=True for added security
                return response
            else:
                print("line----------------140")
                return JsonResponse({'error': 'Access token not found'}, status=400)
        else:
            print("line----------------143")
            return JsonResponse({'error': 'Invalid username or password'}, status=400)
    else:
        print("The request method is: ", request.method)
        form = LoginForm()
        return render(request, 'login.html', {'form': form, 'error_message': 'Invalid username or password'})

#########################  HOME ###########################################################
@csrf_exempt
@never_cache
@permission_classes([IsAuthenticated])
def home(request):
    print("request to the home page--------", request)
    access_token = request.COOKIES.get('access_token') 
    try:
        # Ensure the token is present and has three parts
        print("---------- TOKEN LENGTH-------", len(access_token.split('.')) )
        if not access_token or len(access_token.split('.')) != 3:
            print("HEY SUNITHA THIS IS FROM LINE 147------------------")
            raise InvalidToken('Invalid JWT format')
        # Decode each part of the token and handle padding
        decoded_parts = []
        for i, part in enumerate(access_token.split('.')):
            # Add padding to make the length a multiple of 4
            decoded_part = base64.urlsafe_b64decode(part + '=' * (4 - len(part) % 4))
            try:
                # Try decoding as utf-8
                decoded_part_utf8 = decoded_part.decode('utf-8')
                decoded_parts.append(decoded_part_utf8)
            except UnicodeDecodeError:
                # If utf-8 decoding fails, print the raw bytes
                decoded_parts.append(decoded_part)
        # Check if decoding produced the expected number of parts
        if len(decoded_parts) != 3:
            raise InvalidToken('Invalid number of parts in decoded token')
            
        # Extract the payload and decode as JSON
        payload = decoded_parts[1]
        payload_json = json.loads(payload)
        # Verify the token using PyJWT library
        decoded_token = jwt_decode(access_token, options={"verify_signature": False})

        ####------------exp checking----
        # Decode the token
        decoded_token = jwt_decode(access_token, options={"verify_signature": False})
        
        # Extract the expiration time from the token payload
        expiration_time = decoded_token.get('exp')

        # Check if the token has expired
        current_time = datetime.now(timezone.utc).timestamp()
        if expiration_time and current_time > expiration_time:
            raise InvalidToken('Token has expired')




        user = decoded_token['user_id']
        print("--------------- DECODED TOKEN IS -------------------------------------", user)
        # Continue with JWT authentication
        # authentication = JWTAuthentication()
        user_token, _ = UserToken.objects.get_or_create(user=user)
        print("Authentication Result - Token:-------------------------", user_token)
        print("ID:", user_token.id)
        print("UserToken User Email:", user_token.user.username)
        print("User:", user_token.user)
        
        if user is not None:
            user_details = {
                'username' : user_token.user.username,
                'useremail' : user_token.user.email
            }
            # this is for the profile view restriction
            request.session['visited_home'] = True
            return render(request, 'home.html', {'user_details': user_details})
        else:
            raise InvalidToken('User not authenticated')

    except InvalidToken as e:
        # Log the exception or print it for debugging
        print("HEY SUNITHA THIS IS FROM LINE 209------------------")
        print("Exception:", str(e))
        response = redirect ('/api/login/')
        response.delete_cookie('access_token')
        return response 
    except json.JSONDecodeError as e:
        # Log the exception or print it for debugging
        print("JSON Decode Error:", str(e))
        return JsonResponse({'error': 'Invalid JSON format in token payload'}, status=401)

    except Exception as e:
        # Log the exception or print it for debugging
        print("HEY SUNITHA THIS IS FROM LINE 221------------------")
        print("Exception:", str(e))
        response = redirect('/api/login/')
        response.delete_cookie('access_token')
        return response
        # return JsonResponse({'error': 'Authentication failed or token expired'}, status=401)
    
##################### LOGOUT ################################
@csrf_exempt
@never_cache
def logoutview(request):
    request.session.flush()
    # Clear the access_token cookie
    response = redirect('/api/login/')  # Update '/login' with your actual login page URL
    response.delete_cookie('access_token')
    print("cookie information is deleted-----------------")
    # Disable caching
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'

    return response


################# PROFILE ############################
# @login_required
# def profile(request):
#     print (request.user)
#     user_profile, created = UserProfile.objects.get_or_create(user=request.user)
#     print("hey sunitha-------",user_profile.image_url)
#     if request.method == 'POST':
#         form = UserProfileForm(request.POST, request.FILES, instance=user_profile)
#         url= user_profile.image.url
#         # print("this is url", url)
#         if form.is_valid():
#             user_profile = form.save(commit=False)
#             print("data1-------",user_profile.image_url)
#             user_profile.image_url = url
#             user_profile.save() 
#             print("data2--------",user_profile.image_url)#HERE I NEED TO WORK 
#             return redirect('profile')
#         user_profile.image_url = url
#         user_profile.save()

#     else:
#         form = UserProfileForm(instance=user_profile)
   
#     return render(request, 'profile.html', {'user_profile': user_profile, 'form': form})
from django.core.files.uploadedfile import InMemoryUploadedFile
from io import BytesIO

@login_required
def profile(request):
    print(request.user)
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    
    if request.method == 'POST':
        form = UserProfileForm(request.POST, request.FILES, instance=user_profile)
        url = user_profile.image.url

        # Check if the form is valid before proceeding
        if form.is_valid():
            # Save the form data without committing to the database
            user_profile = form.save(commit=False)
            user_profile.image_url = url
            # Handle Cloudinary upload separately
            if 'profile_images' in request.FILES:
                image_file = request.FILES['image']

                # Check if the file is InMemoryUploadedFile
                if isinstance(image_file, InMemoryUploadedFile):
                    # If so, create a BytesIO object to read the content
                    image_content = BytesIO(image_file.read())
                    user_profile.image = image_content
                else:
                    user_profile.image = image_file

            # Save the UserProfile instance to the database
            user_profile.save()

            return redirect('profile')

    else:
        form = UserProfileForm(instance=user_profile)

    return render(request, 'profile.html', {'user_profile': user_profile, 'form': form})





def delete_image(request):
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    user_profile.image.delete()
    user_profile.save()
    return redirect('profile')


# response = redirect('/api/login/')
# response.delete_cookie('access_token')
# return response