"""
App configuration for annotations app.
"""
from django.apps import AppConfig


class AnnotationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'annotations'
    verbose_name = 'Annotations'
