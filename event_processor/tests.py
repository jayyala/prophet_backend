from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from .models import SuspiciousIPRange, Event, SuspiciousUser, SuspiciousIP
from datetime import datetime, timezone
import json

class SuspiciousIPRangeAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.ip_range = SuspiciousIPRange.objects.create(cidr='192.168.1.0/24')
        self.url = reverse('suspiciousiprrange-list')

    def test_list_ip_ranges(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['cidr'], '192.168.1.0/24')

    def test_create_ip_range(self):
        data = {'cidr': '10.0.0.0/8'}
        response = self.client.post(self.url, data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(SuspiciousIPRange.objects.count(), 2)
        self.assertEqual(SuspiciousIPRange.objects.get(cidr='10.0.0.0/8').cidr, '10.0.0.0/8')

    def test_retrieve_ip_range(self):
        url = reverse('suspiciousiprrange-detail', args=[self.ip_range.id])
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['cidr'], '192.168.1.0/24')

    def test_update_ip_range(self):
        url = reverse('suspiciousiprrange-detail', args=[self.ip_range.id])
        data = {'cidr': '172.16.0.0/12'}
        response = self.client.put(url, data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.ip_range.refresh_from_db()
        self.assertEqual(self.ip_range.cidr, '172.16.0.0/12')

    def test_delete_ip_range(self):
        url = reverse('suspiciousiprrange-detail', args=[self.ip_range.id])
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(SuspiciousIPRange.objects.count(), 0)

class EventProcessingTestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        SuspiciousIPRange.objects.create(cidr='177.0.0.0/8')

    def test_process_events_from_file(self):
        with open('events.jsonl', 'r') as f:
            events = [json.loads(line) for line in f]

        for event in events:
            response = self.client.post(reverse('process-event'), event, format='json')
            self.assertEqual(response.status_code, 201)

        # Check if events from 177.0.0.0/8 are marked as suspicious
        suspicious_events = Event.objects.filter(is_suspicious=True, source_ip__startswith='177.')
        self.assertTrue(suspicious_events.exists())

        # Check if events from other IPs are not marked as suspicious
        normal_events = Event.objects.filter(is_suspicious=False).exclude(source_ip__startswith='177.')
        self.assertTrue(normal_events.exists())

    def test_suspicious_user_propagation(self):
        # Process first event (should be suspicious due to IP)
        event1 = {
            "timestamp": "2024-01-01T00:01:14Z",
            "username": "vevans",
            "source_ip": "177.205.53.245",
            "event_type": "file_download",
            "file_size_mb": 34,
            "application": "email",
            "success": True
        }
        response = self.client.post(reverse('process-event'), event1, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data['is_suspicious'])

        # Process second event (should be suspicious due to user)
        event2 = {
            "timestamp": "2024-01-01T00:02:14Z",
            "username": "vevans",
            "source_ip": "192.168.1.1",
            "event_type": "login",
            "file_size_mb": None,
            "application": "web",
            "success": True
        }
        response = self.client.post(reverse('process-event'), event2, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data['is_suspicious'])

        # Check if user is marked as suspicious
        self.assertTrue(SuspiciousUser.is_suspicious('vevans'))

    def test_suspicious_ip_propagation(self):
        # Process first event (not suspicious)
        event1 = {
            "timestamp": "2024-01-01T00:01:14Z",
            "username": "jdoe",
            "source_ip": "192.168.1.1",
            "event_type": "login",
            "file_size_mb": None,
            "application": "web",
            "success": True
        }
        response = self.client.post(reverse('process-event'), event1, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertFalse(response.data['is_suspicious'])

        # Process second event (suspicious due to IP range)
        event2 = {
            "timestamp": "2024-01-01T00:02:14Z",
            "username": "jsmith",
            "source_ip": "177.205.53.245",
            "event_type": "file_download",
            "file_size_mb": 34,
            "application": "email",
            "success": True
        }
        response = self.client.post(reverse('process-event'), event2, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data['is_suspicious'])

        # Process third event (should be suspicious due to IP)
        event3 = {
            "timestamp": "2024-01-01T00:03:14Z",
            "username": "awhite",
            "source_ip": "177.205.53.245",
            "event_type": "login",
            "file_size_mb": None,
            "application": "web",
            "success": True
        }
        response = self.client.post(reverse('process-event'), event3, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data['is_suspicious'])

        # Check if IP is marked as suspicious
        self.assertTrue(SuspiciousIP.is_suspicious('177.205.53.245'))

class SuspiciousEventsAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('suspicious-events')
        
        # Create some suspicious and non-suspicious events
        for i in range(5):
            Event.objects.create(
                timestamp=datetime.now(timezone.utc),
                username=f'user{i}',
                source_ip=f'192.168.1.{i}',
                event_type='login',
                application='web',
                success=True,
                is_suspicious=True
            )
        
        for i in range(5):
            Event.objects.create(
                timestamp=datetime.now(timezone.utc),
                username=f'user{i+5}',
                source_ip=f'10.0.0.{i}',
                event_type='login',
                application='web',
                success=True,
                is_suspicious=False
            )

    def test_list_suspicious_events(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 5)  # Assuming default page size is greater than 5
        for event in response.data['results']:
            self.assertTrue(event['is_suspicious'])

    def test_pagination(self):
        response = self.client.get(f'{self.url}?page_size=2')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
        self.assertIsNotNone(response.data['next'])
        self.assertIsNone(response.data['previous'])

        # Test next page
        next_page_url = response.data['next']
        response = self.client.get(next_page_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
        self.assertIsNotNone(response.data['previous'])
