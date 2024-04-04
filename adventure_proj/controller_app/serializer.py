from rest_framework import serializers
from .models import ChatHistory,chatMessage
class ChatHistorySerializer(serializers.ModelSerializer):
    messages = serializers.SerializerMethodField()
    class Meta:
        model=ChatHistory
        fields = ['messages']
    
    #obj refers to this user's chatHistory
    def get_messages(self,obj):
        all_messages = obj.chatMessages.all()
        #all messages is a query set of chatMessage objects, to get their messages it is the field message
        message_list = [chat_message.message for chat_message in all_messages]
        return message_list

