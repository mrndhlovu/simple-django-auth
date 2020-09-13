from knox import views as knox_views
from django.urls import path, include


API_VERSION = 'v1/api/'

urlpatterns = [
    path('api/auth', include('knox.urls')),

]
