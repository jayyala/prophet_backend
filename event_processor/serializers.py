from rest_framework import serializers
from .models import SuspiciousIPRange, Event

class SuspiciousIPRangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = SuspiciousIPRange
        fields = ['id', 'cidr']

class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = ['id', 'timestamp', 'username', 'source_ip', 'event_type', 'file_size_mb', 'application', 'success', 'is_suspicious']
