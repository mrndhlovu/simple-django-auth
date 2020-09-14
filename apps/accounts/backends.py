from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.conf import settings

import jwt
from rest_framework import authentication, exceptions


class CaseInsensitiveModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        User = get_user_model()
        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)
        try:
            case_insensitive_username_field = f'{User.USERNAME_FIELD}__iexact'
            user = User._default_manager.get(
                **{case_insensitive_username_field: username})
        except User.DoesNotExist:
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user


# class JWTAuthentication(authentication.BaseAuthentication):
#     def authenticate(self, request):
#         auth_data = authentication.get_authorization_header(request)

#         if not auth_data:
#             return None

#         prefix, token = auth_data.decode('utf-8').split(' ')

#         try:
#             payload = jwt.decode(
#                 token, settings.JWT_SECRET_KEY, algorithm='HS256')
#             user = User.objects.get(email=payload['email'])
#             return (user, token)
#         except jwt.DecodeError:
#             raise exceptions.AuthenticationFailed('Token in invalid')
#         except jwt.ExpiredSignatureError:
#             raise exceptions.AuthenticationFailed(
#                 'Token provided has expired.')
