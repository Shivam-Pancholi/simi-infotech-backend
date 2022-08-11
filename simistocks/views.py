import requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from simistocks.models import Userdata


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def simidata(request):
    print(request.user.id)
    user = Userdata.objects.filter(user_id=request.user.id).first()
    file_name = user.file_name
    data = user.data
    resp = requests.get("http://simistocks.com/login/%s.json" % file_name)
    resp = resp.json().get("ENVELOPE")
    if not data:
        user.data = resp
        user.save()
    for k, v in resp.items():
        v["id"] = k.split("_")[1]
    return Response(list(resp.values()))
