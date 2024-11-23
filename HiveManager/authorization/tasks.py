from celery import shared_task
from django.core.mail import send_mail
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@shared_task
def send_verification_email(email, verification_url):
    logger.info(f"Attempting to send email to {email}")
    subject = 'Verify your email'
    message = f'Click the link to verify your email: {verification_url}'
    send_mail(subject, message, 'your-email@gmail.com', [email])


@shared_task
def test_task():
    return "Celery is working correctly!"
