from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.contrib.auth import authenticate

from rest_framework import status, permissions
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.generics import UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .serializers import(
    LoginSerializer, RegistrationSerializer, UpdateUserSerializer, ChangePasswordSerializer)
from ..models import User


def validate_email(email):
    user = None
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return None
    if user != None:
        return email


@api_view(['GET', ])
@permission_classes(())
@authentication_classes([])
def api_overview(request):
    auth_urls = {
        "Login": '/v1/auth/login',
        "Logout": '/v1/auth/logout',
        "Update Name & Email": '/v1/auth/update',
        "Update Password": '/v1/auth/update-password',
        "Delete": '/v1/auth/delete-account',
        "Register": '/v1/auth/register',
        "UserInfo": '/v1/auth/me',
    }
    return Response(auth_urls)


@ api_view(['GET', ])
@permission_classes((IsAuthenticated,))
def user_api_view(request):
    try:
        user = request.user
    except:
        data = {
            'message': f'User not found',
        }
        return Response(status=status.HTTP_404_NOT_FOUND, data=data)
    serializer = UpdateUserSerializer(user)

    return Response(status=status.HTTP_200_OK, data=serializer.data)


@api_view(['POST', ])
@permission_classes(())
def registration_api_view(request):

    data = {}
    email = request.data['email']
    if validate_email(email) != None:
        data['message'] = 'That email is already in use.'
        return Response(data, status=status.HTTP_400_BAD_REQUEST)

    serializer = RegistrationSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()
        data['email'] = user.email.lower()
        data['full_name'] = user.full_name
        token = Token.objects.get(user=user).key
        data['token'] = token
        return Response(data)
    else:
        data = serializer.errors
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST', ])
@permission_classes(())
def log_api_view(request):
    email = request.data['username']
    password = request.data['password']
    user = authenticate(email=email, password=password)
    context = {}
    if user:
        try:
            token = Token.objects.get(user=user)
        except Token.DoesNotExist:
            token = Token.objects.create(user=user)
        context['email'] = email.lower()
        context['full_name'] = user.full_name
        context['token'] = token.key
        return Response(context)
    else:
        context['message'] = 'Invalid credentials'
        return Response(context, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT', ])
@permission_classes((IsAuthenticated,))
def update_api_view(request):
    data = request.data
    context = {}
    try:
        user = request.user
        serializer = UpdateUserSerializer(user, data=data)
    except:
        return Response(status=status.HTTP_404_NOT_FOUND, data={'message': 'Account not found.'})

    if serializer.is_valid():
        serializer.save()
        context['message'] = 'Update successful'
        return Response(data=context)
    else:
        context = serializer.errors
        return Response(context, status=status.HTTP_400_BAD_REQUEST)


@ api_view(['GET', ])
def verify_account_api_view(request):
    email = request.data['email']
    try:
        existing_user = get_object_or_404(User, email=email)
    except:
        data = {
            'message': f'User with email: {email} not found',
            "exists": False
        }
        return Response(status=status.HTTP_404_NOT_FOUND, data=data)
    if existing_user:
        return Response(status=status.HTTP_200_OK)


@ api_view(['DELETE', ])
@ permission_classes((IsAuthenticated,))
def delete_user_api_view(request):
    try:
        existing_user = request.user
    except:
        data = {
            'message': f'Failed to delete account, Token might have expired.',
        }
        return Response(status=status.HTTP_404_NOT_FOUND, data=data)
    if existing_user:
        existing_user.delete()
        return Response(status=status.HTTP_200_OK, data={'message': 'Account deleted.'})


class UpdatePasswordAPIView(UpdateAPIView):

    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)
    authentication_classes = (TokenAuthentication,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            print("self", self.object.check_password)
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response(status=status.HTTP_404_NOT_FOUND, data={'message': 'Wrong password'})

            new_password = serializer.data.get('new_password')
            confirm_new_password = serializer.data.get('confirm_new_password')
            print("confirm_new_password", confirm_new_password)

            if new_password != confirm_new_password:
                return Response(status=status.HTTP_404_NOT_FOUND, data={'message': 'New passwords must match.'})

            self.object.set_password(
                serializer.data.get('confirm_new_password'))
            self.object.save()
            return Response(status=status.HTTP_200_OK, data={'message': 'Password updated.'})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
