# Suspicious Event Detector

This project is a Django-based API for detecting and managing suspicious events based on IP ranges, user behavior, and IP addresses.

## Features

- Process incoming events and determine if they are suspicious
- Manage suspicious IP ranges
- Retrieve paginated list of suspicious events
- Automatically mark users and IPs as suspicious based on event data

## Installation

1. Clone the repository
2. Install the required dependencies:
   ```
   pip install requirements.txt
   ```
3. Run migrations:
   ```
   python manage.py migrate
   ```
4. Start the development server:
   ```
   python manage.py runserver
   ```
5. Run Tests    
   ```
   python manage.py test
   ```
   

## API Endpoints

### Suspicious IP Ranges

- `GET /api/suspicious-ip-ranges/`: List all suspicious IP ranges
- `POST /api/suspicious-ip-ranges/`: Create a new suspicious IP range
- `GET /api/suspicious-ip-ranges/<id>/`: Retrieve a specific suspicious IP range
- `PUT /api/suspicious-ip-ranges/<id>/`: Update a specific suspicious IP range
- `DELETE /api/suspicious-ip-ranges/<id>/`: Delete a specific suspicious IP range

### Event Processing

- `POST /api/process-event/`: Process a new event

### Suspicious Events

- `GET /api/suspicious-events/`: Retrieve a paginated list of suspicious events

## Code Structure

The main logic for the API is contained in the `views.py` file


### Key Components

1. `SuspiciousIPRangeViewSet`: Handles CRUD operations for suspicious IP ranges.
2. `process_event`: Processes incoming events and determines if they are suspicious based on IP ranges, user history, and IP history.
3. `suspicious_events`: Retrieves a paginated list of suspicious events.

## Models

The application uses the following models:

- `SuspiciousIPRange`: Stores ranges of suspicious IP addresses
- `Event`: Represents an event with associated data (source IP, username, timestamp, etc.)
- `SuspiciousUser`: Tracks users who have been involved in suspicious events
- `SuspiciousIP`: Tracks IP addresses that have been involved in suspicious events

## Pagination

The `suspicious_events` endpoint uses pagination to handle large numbers of events efficiently.
