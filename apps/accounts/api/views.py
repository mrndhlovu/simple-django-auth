from django.shortcuts import get_object_or_404
from django.contrib.auth import authenticate, get_user_model

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.generics import UpdateAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken


from .serializers import(
    RegistrationSerializer,
    UpdateUserSerializer,
    ChangePasswordSerializer
)

User = get_user_model()


def validate_email(email):
    user = None
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return None
    if user != None:
        return email


def get_user_with_tokens(user):
    refresh = RefreshToken.for_user(user)
    return {
        'user': {
            'full_name': user.full_name,
            'email': user.email,
        },
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


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
        data = {'message': f'User not found'}
        return Response(status=status.HTTP_404_NOT_FOUND, data=data)
    serializer = UpdateUserSerializer(user)

    return Response(status=status.HTTP_200_OK, data=serializer.data)


@api_view(['POST', ])
@permission_classes(())
def registration_api_view(request):

    email = request.data['email']
    if validate_email(email) != None:
        data = {}
        data['message'] = 'That email is already in use.'
        return Response(data, status=status.HTTP_400_BAD_REQUEST)

    serializer = RegistrationSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()
        data = get_user_with_tokens(user)
        return Response(data)
    else:
        data = serializer.errors
        return Response(data, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST', ])
@permission_classes(())
def log_api_view(request):

    user = authenticate(
        email=request.data['email'].lower(),
        password=request.data['password']
    )
    if user:
        data = get_user_with_tokens(user)
        return Response(data=data,)
    else:
        data = {'message': 'Invalid credentials'}
        return Response(data=data, status=status.HTTP_400_BAD_REQUEST)


@ api_view(['PUT', ])
@ permission_classes((IsAuthenticated,))
def update_api_view(request):
    data = request.data
    context = {}
    try:
        user = request.user
        serializer = UpdateUserSerializer(user, data=data)
    except:
        data = {'message': 'Account not found.'}
        return Response(status=status.HTTP_404_NOT_FOUND, data=data)

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

            if new_password != confirm_new_password:
                data = {'message': 'New passwords must match.'}
                return Response(status=status.HTTP_404_NOT_FOUND, data=data)

            self.object.set_password(
                serializer.data.get('confirm_new_password'))
            self.object.save()
            return Response(status=status.HTTP_200_OK, data={'message': 'Password updated.'})
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
