from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authentication import authenticate
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from user_app.models import User
# Create your views here.
class SignUp(APIView):
    def post(self,request):
        #create user objects, token object
        #get username and password and ensure they are BOTH entered.
        username = request.data.get("username")
        password = request.data.get("password")
        if username and password:
            user = User.objects.create_user(**request.data)
            token = Token.objects.create(user=user)
            return Response({'user':user.username,'token':token.key},status=status.HTTP_200_OK)
        else:
            return Response("Please enter correct credentials",status=status.HTTP_400_BAD_REQUEST)

class Login(APIView):
    def post(self,request):
        #retrieve login credentials, authenticate. If authenticated then get or create token.
        username = request.data.get('username')
        password = request.data.get('password')
        #looks in database for user entry matching these credentials. Returns none object if not validated.
        user = authenticate(username=username,password=password)
        if user:
            token,created = Token.objects.get_or_create(user=user)
            return Response({"user":username,"token":token.key},status=status.HTTP_200_OK)
        else:
            return Response("Please enter correct credentials",status=status.HTTP_400_BAD_REQUEST)

class LogOut(APIView):
    #this view should only be available once we are logged in
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    #simply destroy the token
    def post(self,request):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)