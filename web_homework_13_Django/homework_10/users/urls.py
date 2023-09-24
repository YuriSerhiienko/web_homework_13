from django.urls import path
from .views import RegisterView
from django.contrib.auth.views import LoginView, LogoutView
from .forms import LoginForm
from django.views.generic import TemplateView
from django.contrib.auth.views import (
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from . import views

app_name = "users"

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path(
        "login/",
        LoginView.as_view(
            redirect_authenticated_user=False,
            template_name="users/login.html",
            authentication_form=LoginForm,
        ),
        name="login",
    ),
    path(
        "profile/",
        TemplateView.as_view(template_name="users/index.html"),
        name="profile",
    ),
    path(
        "logout/", LogoutView.as_view(template_name="users/logout.html"), name="logout"
    ),
    path("reset-password/", views.ResetPasswordView.as_view(), name="password_reset"),
    path(
        "reset-password/done/",
        PasswordResetDoneView.as_view(template_name="users/password_reset_done.html"),
        name="password_reset_done",
    ),
    path(
        "reset-password/confirm/<uidb64>/<token>/",
        PasswordResetConfirmView.as_view(
            template_name="users/password_reset_confirm.html",
            success_url="/reset-password/complete/",
        ),
        name="password_reset_confirm",
    ),
    path(
        "reset-password/complete/",
        PasswordResetCompleteView.as_view(
            template_name="users/password_reset_complete.html"
        ),
        name="password_reset_complete",
    ),
]
