from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.text import gettext_lazy

from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

User = get_user_model()


class ChangePasswordSerializer(serializers.Serializer):

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_new_password = serializers.CharField(required=True)

    def save(self):
        user = User(
            email=self.validated_data['email'].lower(),
            full_name=self.validated_data['full_name']
        )
        password = self.validated_data['password']
        confirm_password = self.validated_data['confirm_password']

        if password != confirm_password:
            raise serializers.ValidationError(
                {'password': 'Password must match'})

        user.set_password(password)
        user.save()
        return user


class RegistrationSerializer(serializers.ModelSerializer):

    confirm_password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'full_name', 'password', 'confirm_password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def save(self):
        user = User(
            email=self.validated_data['email'].lower(),
            full_name=self.validated_data['full_name']
        )
        password = self.validated_data['password']
        confirm_password = self.validated_data['confirm_password']

        if password != confirm_password:
            raise serializers.ValidationError(
                {'message': 'Password must match'})
        if len(confirm_password) < 6:
            raise serializers.ValidationError(
                {'message': 'Password must must be at least 6 characters'})

        user.set_password(password)
        user.save()
        return user


class UpdateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'full_name']


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        model = User
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):

    confirm_password = serializers.CharField(
        style={'input_type': 'password'}, write_only=True)

    password = serializers.CharField(required=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        model = User
        fields = ['password', 'confirm_password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            if password != confirm_password:
                raise AuthenticationFailed(
                    'Password must match.', 400)

            id = force_str(urlsafe_base64_decode(uidb64))

            user = User.objects.get(id=id)

            has_not_used_token_before = PasswordResetTokenGenerator().check_token(user, token)

            if has_not_used_token_before:

                user.set_password(password)
                user.save()

                return user
            else:
                raise AuthenticationFailed(
                    'Reset token is invalid or has expired.', 401)

        except:
            raise AuthenticationFailed(
                'Reset token is invalid or has expired.', 401)
        return super().validate(attrs)


class BlacklistTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            raise AuthenticationFailed(
                'Reset token is invalid or has expired.', 401)
