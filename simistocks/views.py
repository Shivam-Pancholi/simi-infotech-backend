import requests
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from simistocks.models import Userdata
from rest_framework import parsers, renderers
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.compat import coreapi, coreschema
from rest_framework.response import Response
from rest_framework.schemas import ManualSchema
from rest_framework.schemas import coreapi as coreapi_schema
from rest_framework.views import APIView


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def simidata(request):
    print(request.user.id)
    user = Userdata.objects.filter(user_id=request.user.id).first()
    file_name = user.file_name
    data = user.data
    resp = requests.get("http://simistocks.com/login/%s.json" % file_name)
    resp = resp.json().get("ENVELOPE")
    db_dict = {}
    for k, v in resp.items():
        v["id"] = k.split("_")[1]
        v["row"] = k
        if db_dict.get(v.get('K1')):
            db_dict.get(v.get('K1')).append(v)
        else:
            db_dict[v.get('K1')] = []
            db_dict.get(v.get('K1')).append(v)
        if data:
            if data.get(v.get('K1')):
                del data[v.get('K1')]
    if not data:
        user.data = db_dict
    else:
        user.data = data.update(db_dict)
    user.save()
    return Response(list(user.data.values()))


class ObtainAuthToken(APIView):
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AuthTokenSerializer

    if coreapi_schema.is_enabled():
        schema = ManualSchema(
            fields=[
                coreapi.Field(
                    name="username",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Username",
                        description="Valid username for authentication",
                    ),
                ),
                coreapi.Field(
                    name="password",
                    required=True,
                    location='form',
                    schema=coreschema.String(
                        title="Password",
                        description="Valid password for authentication",
                    ),
                ),
            ],
            encoding="application/json",
        )

    def get_serializer_context(self):
        return {
            'request': self.request,
            'format': self.format_kwarg,
            'view': self
        }

    def get_serializer(self, *args, **kwargs):
        kwargs['context'] = self.get_serializer_context()
        return self.serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'admin': user.is_superuser})


obtain_auth_token = ObtainAuthToken.as_view()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        user = User.objects.create(first_name=request.data.get("first_name"), last_name=request.data.get("last_name"),
                                   email=request.data.get("email"), username=request.data.get("email"),
                                   password=request.data.get("password"))
        Userdata.objects.create(user=user, file_name=request.data.get("file_name"))
        msg = "User Created Successfully"
    else:
        msg = "You don't have rights to perform this action"
    return Response(msg)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        return Response(list(Userdata.objects.all().values("user__id", "user__first_name", "user__last_name",
                                                           "user__is_active", "file_name", "user__email",
                                                           "user__date_joined")))
    else:
        return Response("You don't have rights to perform this action")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        data = request.data
        user = Userdata.objects.filter(user__id=data.get('id')).last()
        user.user.first_name = data.get("first_name")
        user.user.last_name = data.get("last_name")
        user.user.is_active = data.get("is_active")
        user.file_name = data.get("file_name")
        user.user.email = data.get("email")
        user.save()
    else:
        return Response("You don't have rights to perform this action")

