from django.urls import path, include


from .views import (
    api_overview,
    registration_api_view,
    verify_account_api_view,
    delete_user_api_view, update_api_view, log_api_view,
    UpdatePasswordAPIView, user_api_view
)

app_name = 'accounts'

urlpatterns = [
    path('delete-account/', delete_user_api_view, name='delete-account'),
    path('login/', log_api_view, name='login'),
    path('me/', user_api_view, name='me'),
    path('overview/', api_overview, name='overview'),
    path('register/', registration_api_view, name='register'),
    path('update-details/', update_api_view, name='update'),
    path('update-password/', UpdatePasswordAPIView.as_view(),
         name='update_password'),
    path('verify/', verify_account_api_view, name='verify'),

]
