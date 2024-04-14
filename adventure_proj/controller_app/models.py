from django.db import models
from django.utils import timezone

# Create your models here.
#I want to separate each message and have chatHistory as an array of messages. This will help with formatting later.
class ChatHistory(models.Model):
    client = models.OneToOneField('user_app.User',on_delete=models.CASCADE)
    number_of_messages = models.IntegerField(default=0)

    def addMessage(self,chat_message):
        self.number_of_messages+=1
        chat_message.save()
        self.save()


class chatMessage(models.Model):
    chatLog = models.ForeignKey(ChatHistory,on_delete=models.CASCADE,related_name='chatMessages')
    parts = models.TextField()
    role = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    image = models.TextField(null=True,blank=True)

    def __str__(self):
        return self.message