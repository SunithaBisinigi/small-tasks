from django.contrib import admin
from django.urls import path, include
from authenticationApiApp.views import registration, profile, delete_image
from django.conf import settings
from django.conf.urls.static import static



urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('authenticationApiApp.urls')),
    path('registration/', registration, name='registration'),
    path('api/home/profile/', profile, name='profile'),
    path('profile/delete/', delete_image, name='delete_image'),

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)