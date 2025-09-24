"""
URL configuration for Sernion Mark project.
"""
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path
from rest_framework import permissions

# Simple API documentation placeholder

urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API endpoints
    path('api/v1/', include('authentication.urls')),
    path('api/v1/', include('projects.urls')),
    path('api/v1/', include('annotations.urls')),
    
    # API documentation (placeholder)
    path('api/docs/', lambda request: HttpResponse("API Documentation - Coming Soon"), name='api-docs'),
    
    # Token endpoints
    path('api/token/', include('authentication.token_urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
