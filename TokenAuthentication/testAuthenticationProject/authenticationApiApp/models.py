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
    image = models.ImageField(upload_to='profile_images', null=True, blank=True)
    image_url = models.URLField(blank=True,null=True, max_length=2000)

class PdfDocument(models.Model):
    title = models.CharField(max_length=255)
    pdf_file = models.FileField(upload_to='pdf_documents/')
    pdf_file_url = models.URLField(blank=True, null=True)

