from django.contrib import admin
from django.urls import path, include

from HiveManager.authorization.views import home_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home_view, name='home'),  # Домашняя страница доступна по пустому пути
    path('api/authorization/', include('HiveManager.authorization.urls')),
    path('api/users/', include('HiveManager.users.urls')),
    path('api/tasks/', include('HiveManager.tasks.urls')),
]
