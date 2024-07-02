from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/simi/', consumers.SimiConsumer.as_asgi()),
]
