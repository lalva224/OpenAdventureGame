from rest_framework import serializers
from .models import ChatHistory,chatMessage
class ChatHistorySerializer(serializers.ModelSerializer):
    messages = serializers.SerializerMethodField()
    class Meta:
        model=ChatHistory
        fields = ['messages']
    
    #obj refers to this user's chatHistory
    def get_messages(self,obj):
        all_messages = obj.chatMessages.all().order_by('created_at')
        serialized_messages = ChatMessageSerializer(all_messages,many=True)
        return serialized_messages.data

class ChatHistoryAISerializer(serializers.ModelSerializer):
    messages = serializers.SerializerMethodField()
    class Meta:
        model=ChatHistory
        fields = ['messages']
    
    #obj refers to this user's chatHistory
    def get_messages(self,obj):
        all_messages = obj.chatMessages.all().order_by('created_at')
        serialized_messages = ChatMessageAISerializer(all_messages,many=True)
        return serialized_messages.data

class ChatMessageSerializer(serializers.ModelSerializer):
    # part = serializers.SerializerMethodField()
    class Meta:
        model = chatMessage
        fields = ['role','parts','created_at','image']

class ChatMessageAISerializer(serializers.ModelSerializer):
    # part = serializers.SerializerMethodField()
    class Meta:
        model = chatMessage
        fields = ['role','parts']
    
    
        

