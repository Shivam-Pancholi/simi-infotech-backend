from django.contrib import admin
from django.urls import path
from simistocks.views import simidata

urlpatterns = [
    path('simidata', simidata),
]
