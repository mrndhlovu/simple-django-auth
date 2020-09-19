from django.db import models
from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager)
from django.urls import reverse
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError, smart_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site

from rest_framework_simplejwt.tokens import RefreshToken


class UserManager(BaseUserManager):
    def create_user(self, email, full_name, password=None, is_active=True, is_staff=False, is_admin=False, is_verified=False):
        if not email:
            raise ValueError('Users must have an email address')
        if not password:
            raise ValueError('Users must have a password')
        if not full_name:
            raise ValueError('Users must have a full name')
        user = self.model(
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.staff = is_staff
        user.full_name = full_name
        user.admin = is_admin
        user.active = is_active
        user.is_verified = is_verified
        user.save(using=self._db)

        return user

    def create_staffuser(self, email, full_name, password):
        user = self.create_user(
            email, full_name, password=password,
        )
        user.staff = True
        user.is_verified = True
        user.save(using=self._db)

        return user

    def create_superuser(self, email, full_name, password=None):
        user = self.create_user(
            email, full_name, password=password,
        )
        user.admin = True
        user.staff = True
        user.confirmed = True
        user.is_verified = True
        user.save(using=self._db)
        return user


class User (AbstractBaseUser):
    email = models.EmailField(max_length=255, unique=True)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    active = models.BooleanField(default=True)
    admin = models.BooleanField(default=False)
    staff = models.BooleanField(default=False)
    confirmed = models.BooleanField(default=False)
    time_stamp = models.DateTimeField(auto_now=True)
    confirmed_date = models.DateTimeField(auto_now=False, null=True)

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['full_name']

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    def get_full_name(self):
        if self.full_name:
            return self.full_name
        return self.email

    def get_short_name(self):
        if self.full_name:
            return self.full_name
        return self.email

    @property
    def is_admin(self):
        return self.admin

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_active(self):
        return self.active

    def with_auth_tokens(self):
        refresh = RefreshToken.for_user(self)

        return {
            'user': {
                'full_name': self.full_name,
                'email': self.email,
                'confirmed': self.confirmed,
            },
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }
