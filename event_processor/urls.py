from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SuspiciousIPRangeViewSet, process_event, suspicious_events

router = DefaultRouter()
router.register(r'suspicious-ip-ranges', SuspiciousIPRangeViewSet, basename='suspiciousiprrange')

urlpatterns = [
    path('', include(router.urls)),
    path('process-event/', process_event, name='process-event'),
    path('suspicious-events/', suspicious_events, name='suspicious-events'),
]