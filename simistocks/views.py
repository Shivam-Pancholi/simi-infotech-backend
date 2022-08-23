import requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from simistocks.models import Userdata
from rest_framework import parsers, renderers, generics
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.compat import coreapi, coreschema
from rest_framework.response import Response
from rest_framework.schemas import ManualSchema
from rest_framework.schemas import coreapi as coreapi_schema
from rest_framework.views import APIView
import copy
import json
# from rest_framework import serializers
from django.contrib.auth.models import User
# from rest_framework.validators import UniqueValidator
# from django.contrib.auth.password_validation import validate_password


# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(
#         required=True,
#         validators=[UniqueValidator(queryset=User.objects.all())]
#     )
#
#     password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
#
#     class Meta:
#         model = User
#         fields = ('username', 'password', 'email')
#
#     def create(self, validated_data):
#         user = User.objects.create(
#             username=validated_data['username'],
#             email=validated_data['email'],
#         )
#         user.set_password(validated_data['password'])
#         user.save()
#
#         return user


# class RegisterView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     permission_classes = (AllowAny,)
#     serializer_class = RegisterSerializer


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def simidata(request):
    user = Userdata.objects.filter(user_id=request.user.id).first()
    file_name = user.file_name
    data = user.data
    resp = requests.get("http://simistocks.com/login/%s.json" % file_name)
    resp = resp.json().get("ENVELOPE")
    if resp == data.get("last_updated_data"):
        return Response(sum(list(data.get("data").values()), []))
    db_dict = {}
    last_data = copy.deepcopy(resp)
    for k, v in resp.items():
        v["id"] = k.split("_")[1]
        v["row"] = k
        if db_dict.get(v.get('K1')):
            db_dict.get(v.get('K1')).append(v)
        else:
            db_dict[v.get('K1')] = []
            db_dict.get(v.get('K1')).append(v)
        if data:
            if data.get("data").get(v.get('K1')):
                del data["data"][v.get('K1')]
    if not data:
        user.data = {"data": db_dict, "last_updated_data": resp}
    else:
        data.get("data").update(db_dict)
        user.data = {"data": data.get("data"), "last_updated_data": last_data}
    user.save()
    return Response(sum(list(data.get("data").values()), []))


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
        templates = Userdata.objects.filter(user=user).last().templates
        return Response({'token': token.key, 'admin': user.is_superuser, 'templates': templates})


obtain_auth_token = ObtainAuthToken.as_view()


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        user = User.objects.create(email=request.data.get("email"), username=request.data.get("email"))
        user.set_password(request.data.get("password"))
        user.save()
        Userdata.objects.create(user=user, file_name=request.data.get("file_name"),
                                whatsapp_phone_no_id=request.data.get("whatsapp_phone_no_id"),
                                whatsapp_token=request.data.get("whatsapp_token"),
                                templates=request.data.get("templates", []))
        msg = "User Created Successfully"
    else:
        msg = "You don't have rights to perform this action"
    return Response(msg)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_users(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        return Response(list(Userdata.objects.all().values("user__id", "user__is_active", "file_name", "user__email",
                                                           "user__date_joined", "whatsapp_phone_no_id", "whatsapp_token",
                                                           "templates")))
    else:
        return Response("You don't have rights to perform this action")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_user(request):
    admin = User.objects.filter(id=request.user.id).last().is_superuser
    if admin:
        data = request.data
        user = Userdata.objects.filter(user__id=data.get('id')).last()
        user.user.is_active = data.get("is_active")
        user.file_name = data.get("file_name")
        user.user.email = data.get("email")
        user.whatsapp_token = data.get("whatsapp_token")
        user.whatsapp_phone_no_id = data.get("whatsapp_phone_no_id")
        user.templates = data.get("templates")
        user.user.save()
        user.save()
        return Response("Success")
    else:
        return Response("You don't have rights to perform this action")


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def simi_whatsapp(request):
    data_dict = {}
    data = request.data
    user = Userdata.objects.filter(user__id=request.user.id).last()
    phone_id = user.whatsapp_phone_no_id
    token = user.whatsapp_token
    url = "https://graph.facebook.com/v13.0/%s/messages" % phone_id
    print(request.data)
    print(request.data.get("phone_numbers"))
    for numbers in request.data.get("phone_numbers"):
        payload = json.dumps({
          "messaging_product": "whatsapp",
          "to": numbers,
          "type": "template",
          "template": {
            "name": "%s" % request.data.get("template", "hello_world"),
            "language": {
              "code": "en_US"
            }
          }
        })
        headers = {
          'Authorization': 'Bearer %s' % token,
          'Content-Type': 'application/json'
        }

        response = requests.request("POST", url, headers=headers, data=payload).json()
        data_dict[str(numbers)] = "success" if response.get("messages")[0].get("id") else "error"
    return Response(data_dict)
