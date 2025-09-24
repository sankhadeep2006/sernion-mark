"""
WSGI config for Sernion Mark project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sernion_mark.settings')

application = get_wsgi_application()
