from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import render, redirect
from django.contrib import messages
from rest_framework.permissions import AllowAny, IsAuthenticated
from HiveManager.authorization.tasks import send_verification_email

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from HiveManager.authorization.forms import UserRegistrationForm, UserLoginForm

User = get_user_model()


# === Регистрация через API ===
class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')

        if not email or not password or not first_name or not last_name:
            return Response({"error": "All fields are required."}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({"error": "Email is already in use."}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(email=email, password=password, first_name=first_name, last_name=last_name)
        user.is_active = False  # Ставим неактивным до подтверждения email

        # Отправка email подтверждения
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        verification_url = f"http://localhost:8000/api/authorization/verify-email/?uid={uid}&token={token}"
        send_mail(
            subject="Verify Your Email",
            message=f"Click the link to verify your email: {verification_url}",
            from_email="no-reply@example.com",
            recipient_list=[email],
        )

        return Response({"message": "User registered successfully. Please verify your email."},
                        status=status.HTTP_201_CREATED)


# === Подтверждение email ===
from django.shortcuts import redirect
from django.http import HttpResponseRedirect


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        uid = request.GET.get('uid')
        token = request.GET.get('token')

        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
            if default_token_generator.check_token(user, token):
                user.is_active = True
                user.save()
                # Перенаправление на главную страницу или страницу подтверждения
                return redirect('home')  # Укажите правильное имя маршрута
        except Exception:
            pass

        return redirect('login')  # Если токен невалидный, перенаправляем на страницу логина


# === Получение и обновление данных пользователя ===
class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
        })

    def put(self, request):
        user = request.user
        user.first_name = request.data.get("first_name", user.first_name)
        user.last_name = request.data.get("last_name", user.last_name)
        user.save()
        return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)


# === Управление пользователями для администратора ===
class UserListView(APIView, PageNumberPagination):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_staff:
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        users = User.objects.all()
        results = self.paginate_queryset(users, request, view=self)
        serialized_users = [
            {"id": user.id, "email": user.email, "first_name": user.first_name, "last_name": user.last_name} for user in
            results]
        return self.get_paginated_response(serialized_users)


class UserDetailAdminView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        if not request.user.is_staff:
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = User.objects.get(pk=user_id)
            return Response({"email": user.email, "first_name": user.first_name, "last_name": user.last_name})
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, user_id):
        if not request.user.is_staff:
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        try:
            user = User.objects.get(pk=user_id)
            user.first_name = request.data.get("first_name", user.first_name)
            user.last_name = request.data.get("last_name", user.last_name)
            user.save()
            return Response({"message": "User updated successfully."}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


def register_view(request):
    if request.method == "POST":
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password'])
            user.is_active = False  # Ставим пользователя неактивным до подтверждения
            user.save()

            # Генерация токена для подтверждения email
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            verification_url = f"http://localhost:8000/api/authorization/verify-email/?uid={uid}&token={token}"

            # Отправка письма
            send_mail(
                subject="Verify Your Email",
                message=f"Click the link to verify your email: {verification_url}",
                from_email="no-reply@example.com",
                recipient_list=[user.email],
            )

            messages.success(request, "Registration successful. Please check your email to confirm your account.")
            return redirect('email_confirmation')
    else:
        form = UserRegistrationForm()

    return render(request, "auth/register.html", {"form": form})


def login_view(request):
    if request.method == "POST":
        form = UserLoginForm(request, data=request.POST)
        if form.is_valid():
            user = authenticate(request, username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            if user:
                login(request, user)
                messages.success(request, f"Welcome {user.first_name}!")
                return redirect('home')
            else:
                messages.error(request, "Invalid credentials.")
    else:
        form = UserLoginForm()

    return render(request, "auth/login.html", {"form": form})


def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out.")
    return redirect('login')


@login_required
def home_view(request):
    return render(request, "auth/home.html", {"user": request.user})


def send_verification_email_view(request, user):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    verification_url = f"http://localhost:8000/api/authorization/verify-email/?uid={uid}&token={token}"

    send_verification_email.delay(user.email, verification_url)

    return Response({"message": "Verification email sent."}, status=status.HTTP_200_OK)


def verify_email_view(request):
    uid = request.GET.get('uid')
    token = request.GET.get('token')

    try:
        user_id = force_str(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=user_id)
        if default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
    except Exception:
        return Response({"error": "Invalid token or user ID."}, status=status.HTTP_400_BAD_REQUEST)


def email_confirmation_view(request):
    return render(request, "auth/email_confirmation.html")


from django.shortcuts import render


def lockout_view(request):
    return render(request, 'auth/lockout.html', status=403)
