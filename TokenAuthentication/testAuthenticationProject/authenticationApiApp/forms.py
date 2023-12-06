from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User, UserProfile, PdfDocument

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2')

class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields  = ['image', 'image_url']

class PdfDocumentForm(forms.ModelForm):
    class Meta:
        model = PdfDocument
        fields = ['title', 'pdf_file' ]
