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
load_dotenv()

class PromptGemini(APIView):
    def get(self,request):
        while True:
            genai.configure(api_key=os.getenv('API_KEY'))
            model = genai.GenerativeModel('gemini-pro')

            chat = model.start_chat(history=[])

            chat.send_message(PROMPT)
            user_input = request.data.get('user_input')
            if user_input:
                chat.send_message(user_input)
            chatHistory= ''
            for message in chat.history:
                chatHistory+=f'**{message.role}**: {message.parts[0].text}'
            
            return Response(chatHistory,status=status.HTTP_200_OK)


