from django.contrib import admin
from django.urls import path
from simistocks.views import simidata, list_users, update_user, simi_whatsapp

urlpatterns = [
    path('simidata', simidata),
    path('list_users', list_users),
    path('update_user', update_user),
    path('simi_whatsapp', simi_whatsapp)
]
