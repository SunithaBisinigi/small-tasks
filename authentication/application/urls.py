from django.urls import path
from .views import  home, login_view, UserDetailsView

urlpatterns = [
    path('home/', home, name='home'),
    path('login/', login_view, name='login_view'),
    path('user-details/', UserDetailsView.as_view(), name='user-details'),

]

