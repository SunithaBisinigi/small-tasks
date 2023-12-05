from django.db import models
from django.contrib.auth.models import User
from cloudinary.models import CloudinaryField
# from cloudinary_storage.storage import RawMediaCloudinaryStorage

class UserToken(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    access_token = models.CharField(max_length=255)
    refresh_token = models.CharField(max_length=255)
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = CloudinaryField('image')  # Check the correct field name ('image') for your Cloudinary setup
    image_url = models.URLField(blank=True, max_length=2000)
