# accounts/urls.py
from django.urls import path
from .views import refresh_token, verify_session, login_view

urlpatterns = [
    path('login/', login_view),
    path('refresh/', refresh_token),
    path('verify/', verify_session),
]
