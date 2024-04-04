from django.shortcuts import render
import google.generativeai as genai
import os
from rest_framework.views import APIView
from rest_framework.response import Response
from dotenv import load_dotenv
from rest_framework import status
from IPython.display import display
from .prompt import PROMPT
from IPython.display import display
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .models import ChatHistory,chatMessage
from .serializer import ChatHistorySerializer

load_dotenv()

class getNewChat(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        #send original prompt, create new chatHistory object and save it.
        genai.configure(api_key=os.getenv('API_KEY'))
        model = genai.GenerativeModel('gemini-pro')

        chat = model.start_chat(history=[])

        chat.send_message(PROMPT)
        new_message= ''
        for message in chat.history[1:]:
            new_message+=f'**{message.role}**: {message.parts[0].text}'
        
        #have to create a chat history object as it is a new game.
        chat_history = ChatHistory.objects.create(client = request.user)
        chat_history.save()
        #create a new message and connect it to chat log
        chat_message = chatMessage.objects.create(message=new_message,chatLog=chat_history)
        #adds num of messages and saves the chat message object
        ChatHistory.addMessage(chat_message)
        serialized_history = ChatHistorySerializer(chat_history)
        return Response(serialized_history,status=status.HTTP_200_OK)

class PromptGemini(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self,request):
        #check if this user has chatHistory. If not then create a new message sending the og prompt
        chat_history = ChatHistory.objects.get(client = request.user)
        if chat_history:
            serialized_history = ChatHistorySerializer(chat_history)
            genai.configure(api_key=os.getenv('API_KEY'))
            model = genai.GenerativeModel('gemini-pro')
            chat = model.start_chat(history=serialized_history)
            
            prompt = request.data.get('prompt')
            chat.send_message(prompt)
            current_message = chat_history.number_of_messages-1
            
            new_message = ''
            for message in chat.history[current_message:]:
                new_message+=f'**{message.role}**: {message.parts[0].text}'
            
            #create new chat message object
            chat_message = chatMessage(client = request.user,chatLog=chat_history)
            chat_history.addMessage(chat_message)
            updated_serialized_history = ChatHistorySerializer(chat_history)
            return Response(updated_serialized_history,status=status.HTTP_200_OK)

        else:
            return getNewChat.get()
            
            


