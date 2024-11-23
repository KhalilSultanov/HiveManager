from __future__ import absolute_import, unicode_literals
import os
from celery import Celery

# Настройка Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'HiveManager.settings')

app = Celery('HiveManager')

# Используем настройки Django
app.config_from_object('django.conf:settings', namespace='CELERY')

# Автопоиск задач
app.autodiscover_tasks()
