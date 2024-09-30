from django.db import models
from ipaddress import ip_network, ip_address
from django.core.cache import cache

class SuspiciousIPRange(models.Model):
    cidr = models.CharField(max_length=18, unique=True)

    def __str__(self):
        return self.cidr

    def is_ip_in_range(self, ip):
        try:
            return ip_address(ip) in ip_network(self.cidr)
        except ValueError:
            return False

class SuspiciousUser(models.Model):
    user_id = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.user_id

    @classmethod
    def is_suspicious(cls, user_id):
        cache_key = f'suspicious_user_{user_id}'
        is_suspicious = cache.get(cache_key)
        if is_suspicious is None:
            is_suspicious = cls.objects.filter(user_id=user_id).exists()
            cache.set(cache_key, is_suspicious, timeout=3600)  # Cache for 1 hour
        return is_suspicious

class SuspiciousIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __str__(self):
        return self.ip_address

    @classmethod
    def is_suspicious(cls, ip_address):
        cache_key = f'suspicious_ip_{ip_address}'
        is_suspicious = cache.get(cache_key)
        if is_suspicious is None:
            is_suspicious = cls.objects.filter(ip_address=ip_address).exists()
            cache.set(cache_key, is_suspicious, timeout=3600)  # Cache for 1 hour
        return is_suspicious

class Event(models.Model):
    timestamp = models.DateTimeField()
    username = models.CharField(max_length=255)
    source_ip = models.GenericIPAddressField()
    event_type = models.CharField(max_length=50)
    file_size_mb = models.IntegerField(null=True, blank=True)
    application = models.CharField(max_length=50)
    success = models.BooleanField()
    is_suspicious = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username} - {self.source_ip} - {self.event_type} - {'Suspicious' if self.is_suspicious else 'Normal'}"
