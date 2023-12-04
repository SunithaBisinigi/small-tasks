from django.urls import path
from .views import  home,  login_view, logoutview

urlpatterns = [
    path('home/', home, name='home'),
    path('login/', login_view, name='login'),
    path('logout/', logoutview, name='logout'),
    
]