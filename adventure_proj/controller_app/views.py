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
from .serializer import ChatHistorySerializer

load_dotenv()

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

    def get(self,request):
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
        serialized_history = ChatHistorySerializer(chat_history)
        print(serialized_history)
        genai.configure(api_key=os.getenv('API_KEY'))
        model = genai.GenerativeModel('gemini-pro')
        chat = model.start_chat(history=serialized_history.data['messages'])
        
        prompt = request.data.get('prompt')
        print(prompt)
        chat.send_message(prompt)
        current_message = chat_history.number_of_messages
        print('current message:',current_message)
        #chat.history is the actual gemini object containing our history.  index at current message will be for the user prompt. +1 is for the model response
        text_prompt = chat.history[current_message].parts[0].text
        role_prompt = chat.history[current_message].role
        text_response = chat.history[current_message+1].parts[0].text
        role_response = chat.history[current_message+1].role
        
        chat_message_prompt = chatMessage(chatLog=chat_history,parts=text_prompt,role=role_prompt)
        chat_message_response = chatMessage(chatLog=chat_history,parts=text_response,role=role_response)
        chat_history.addMessage(chat_message_prompt)
        chat_history.addMessage(chat_message_response)

        updated_serialized_history = ChatHistorySerializer(chat_history)
        return Response(updated_serialized_history.data['messages'],status=status.HTTP_200_OK)

class End_Game(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]      
    def delete(self,request):
        #delete chat history and bring us a new chat
        chat_history = ChatHistory.objects.get(client=request.user)   
        chat_history.delete() 
        return Response(status=status.HTTP_204_NO_CONTENT)
            

    

