from django.shortcuts import render, redirect
from pytube import *

# Create your models here.
def youtube(request):
    if request.method =="POST":
        link = request.POST['link']
        video = YouTube(link)
        Stream = video.streams.get_highest_resolution()
        Stream.download()
        return render(request, 'index.html')
    return render (request, 'index.html')