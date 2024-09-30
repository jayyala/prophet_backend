from django.core.management.base import BaseCommand
from event_processor.models import Event

class Command(BaseCommand):
    help = 'Deletes all events from the database'

    def handle(self, *args, **kwargs):
        Event.objects.all().delete()
        self.stdout.write(self.style.SUCCESS('Successfully deleted all events'))
