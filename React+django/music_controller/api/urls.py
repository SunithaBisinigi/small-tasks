from .views import RoomView
from django.urls import path

urlpatterns = [
    path('', RoomView.as_view()),
]
