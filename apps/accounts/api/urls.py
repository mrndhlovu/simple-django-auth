
from django.urls import path, include
from .views import api_overview


urlpatterns = [
    path('overview/', api_overview),

]
