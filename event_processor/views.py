from rest_framework import viewsets, status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from .models import SuspiciousIPRange, Event, SuspiciousUser, SuspiciousIP
from .serializers import SuspiciousIPRangeSerializer, EventSerializer

class SuspiciousIPRangeViewSet(viewsets.ModelViewSet):
    queryset = SuspiciousIPRange.objects.all()
    serializer_class = SuspiciousIPRangeSerializer

@api_view(['POST'])
def process_event(request):
    serializer = EventSerializer(data=request.data)
    if serializer.is_valid():
        event = serializer.save(is_suspicious=False)
        
        # Check if IP is in suspicious range
        if any(ip_range.is_ip_in_range(event.source_ip) for ip_range in SuspiciousIPRange.objects.all()):
            event.is_suspicious = True
        
        # Check if user or IP is suspicious (O(1) lookups)
        elif SuspiciousUser.is_suspicious(event.username) or SuspiciousIP.is_suspicious(event.source_ip):
            event.is_suspicious = True
        
        if event.is_suspicious:
            SuspiciousUser.objects.get_or_create(user_id=event.username)
            SuspiciousIP.objects.get_or_create(ip_address=event.source_ip)
        
        event.save()
        return Response(EventSerializer(event).data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SuspiciousEventsPagination(PageNumberPagination):
    page_size = 100
    page_size_query_param = 'page_size'
    max_page_size = 1000

@api_view(['GET'])
def suspicious_events(request):
    events = Event.objects.filter(is_suspicious=True).order_by('-timestamp')
    paginator = SuspiciousEventsPagination()
    result_page = paginator.paginate_queryset(events, request)
    serializer = EventSerializer(result_page, many=True)
    return paginator.get_paginated_response(serializer.data)
