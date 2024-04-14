from django.shortcuts import render
import google.generativeai as genai
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from dotenv import load_dotenv
from rest_framework import status
from .prompt import PROMPT
from IPython.display import display
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .models import ChatHistory,chatMessage
from .serializer import ChatHistorySerializer,ChatMessageAISerializer,ChatHistoryAISerializer
from openai import OpenAI
from .prompt import IMAGERY
import requests
import io
from PIL import Image
import time
from google.cloud import storage
from google.oauth2 import service_account
from django.http import JsonResponse
import json
import boto3
import requests
from django.views.decorators.http import require_http_methods

load_dotenv()

s3 = boto3.client(
    's3',
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)
    
class getNewChat(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def post(self,request):
        print('inside get new chat')
        #send original prompt, create new chatHistory object and save it.
        genai.configure(api_key=os.getenv('API_KEY'))
        model = genai.GenerativeModel('gemini-pro')

        chat = model.start_chat(history=[])

        chat.send_message(PROMPT)
        text1= chat.history[0].parts[0].text
        role1 = chat.history[0].role
        text2= chat.history[1].parts[0].text
        role2 = chat.history[1].role

        
        #have to create a chat history object as it is a new game.
        chat_history = ChatHistory.objects.create(client = request.user)
        chat_history.save()
        #create a new message and connect it to chat log
        chat_message_first_prompt = chatMessage.objects.create(chatLog=chat_history, parts=text1, role = role1)
        chat_message_first_response = chatMessage.objects.create(chatLog=chat_history, parts=text2, role = role2)
        #adds num of messages and saves the chat message object
        chat_history.addMessage(chat_message_first_prompt)
        chat_history.addMessage(chat_message_first_response)
        serialized_history = ChatHistorySerializer(chat_history)
        return Response(serialized_history.data['messages'],status=status.HTTP_200_OK)

class Start(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self,request):
        #check chat history, if none create. If there is just retrieve it.
        try:
            chat_history = ChatHistory.objects.get(client = request.user)
            serialized_history = ChatHistorySerializer(chat_history)
            return Response(serialized_history.data['messages'],status=status.HTTP_200_OK)
        except ChatHistory.DoesNotExist:
            return getNewChat.post(self,request)
        
class PromptGemini(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self,request):
        #check if this user has chatHistory. If not then create a new message sending the og prompt
        chat_history = ChatHistory.objects.get(client = request.user)
        serialized_history = ChatHistoryAISerializer(chat_history)
        genai.configure(api_key=os.getenv('API_KEY'))
        model = genai.GenerativeModel('gemini-pro')
        chat = model.start_chat(history=serialized_history.data['messages'])
        
        prompt = request.data.get('prompt')
        chat.send_message(prompt)
        current_message = chat_history.number_of_messages
        #chat.history is the actual gemini object containing our history.  index at current message will be for the user prompt. +1 is for the model response
        text_prompt = chat.history[current_message].parts[0].text
        role_prompt = chat.history[current_message].role

        text_response = chat.history[current_message+1].parts[0].text
        role_response = chat.history[current_message+1].role
        
        chat_message_prompt = chatMessage.objects.create(chatLog=chat_history,parts=text_prompt,role=role_prompt)
        chat_message_response = chatMessage.objects.create(chatLog=chat_history,parts=text_response,role=role_response)
        chat_history.addMessage(chat_message_prompt)
        chat_history.addMessage(chat_message_response)
        
        
        updated_serialized_history = ChatHistorySerializer(chat_history)
        print(updated_serialized_history.data['messages'])
        return Response(updated_serialized_history.data['messages'],status=status.HTTP_200_OK)


class End_Game(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]      
    def delete(self,request):
        #delete chat history and bring us a new chat
        chat_history = ChatHistory.objects.get(client=request.user)   
        chat_history.delete() 
        return Response(status=status.HTTP_204_NO_CONTENT)
            
class get_Image(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self,request):
        #get chat history
        chat_history = ChatHistory.objects.get(client = request.user)
        serialized_history = ChatHistoryAISerializer(chat_history)
        genai.configure(api_key=os.getenv('API_KEY'))
        model = genai.GenerativeModel('gemini-pro')
        chat = model.start_chat(history=serialized_history.data['messages'])

        #send request for imagery of current situation
        chat.send_message('Provide me with descriptive text/imagery of the current situation. Provide me with good visual text.')
        current_message = chat_history.number_of_messages
        imagery = chat.history[current_message+1].parts[0].text
        print('\n\n\n\n',imagery,'\n\n\n\n')


        #send imagery to DALLE
        client = OpenAI(api_key=os.getenv('CHAT_KEY'))
        response = client.images.generate(model="dall-e-3",prompt=imagery,size="1024x1024",quality="standard",n=1)
        image_url = response.data[0].url

        #save image to google cloud and retrieve its url.
        cloud_url = save_image(image_url)

        #need to get current message from user's chat history
        #actual current message is the imagery
        latest_chat_message =chatMessage.objects.latest('created_at')
        latest_chat_message.image = cloud_url
        latest_chat_message.save()
        chat_history.save()
        print(latest_chat_message.image)
        return Response(cloud_url,status=status.HTTP_200_OK)
    


def save_image(temp_image):
    try:
        image_url = temp_image
        #we need to turn it into a jpg (bc dalle urls expire after 1 hr) then store into google cloud and retrieve that url
        # Fetch the image data from the provided URL
        response = requests.get(image_url)
        image_data = io.BytesIO(response.content)
        
        # Open image using PIL
        image = Image.open(image_data)
        
        # Convert the image to JPEG format
        output = io.BytesIO()
        image.save(output, format='JPEG')
        jpeg_data = output.getvalue()
        
        # Create a unique filename
        filename = f"{int(time.time())}.jpeg"
        
        s3.put_object(Body=jpeg_data, Bucket='openadventureimages', Key=filename, ContentType='image/jpeg')

        # Get the URL of the uploaded image
        image_url = f"https://openadventureimages.s3.amazonaws.com/{filename}"
        return image_url
    except Exception as e:
          print('Error proxying image:', e)
          return JsonResponse({'error': 'An error occurred while proxying the image'}, status=500)


class create_download_copy(APIView):
    def post(self,request):
        # URL of the JPEG image stored in AWS S3
        s3_image_url = request.data.get('s3_url')
        print('s3 image url:',s3_image_url)
        # Send a GET request to download the image
        try:
            response = requests.get(s3_image_url)
            if response.status_code == 200:
                # Save the image to a local file
                with open("local_image.jpeg", "wb") as f:
                    f.write(response.content)
                    print('success')
                return Response(status=status.HTTP_200_OK)
                # Now you have a local copy of the image named "local_image.jpeg"
            else:
                print("Failed to download image. Status code:", status=response.status_code)
        except Exception as e:
            print(e)
            return Response(e, status=status.HTTP_400_BAD_REQUEST)