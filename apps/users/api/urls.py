
from django.urls import path, include
from .views import API_OVERVIEW


urlpatterns = [
    path('overview/', API_OVERVIEW),

]
