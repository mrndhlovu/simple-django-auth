from django.shortcuts import render
from django.http import JsonResponse

from rest_framework.decorators import api_view
from rest_framework.response import Response


@api_view(['GET'])
def api_overview(request):
    auth_urls = {
        "Login": '/v1/auth/login',
        "Logout": '/v1/auth/logout',
        "Update": '/v1/auth/update',
        "Delete": '/v1/auth/delete-account',
        "Register": '/v1/auth/register',
    }
    return Response(auth_urls)
