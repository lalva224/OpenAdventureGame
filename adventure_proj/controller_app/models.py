from django.db import models

# Create your models here.
#I want to separate each message and have chatHistory as an array of messages. This will help with formatting later.
class ChatHistory(models.Model):
    client = models.OneToOneField('user_app.User',on_delete=models.CASCADE)
    number_of_messages = models.IntegerField(default=0)

    def addMessage(self,chat_message):
        self.number_of_messages+=1
        self.save()
        chat_message.save()

    
class chatMessage(models.Model):
    chatLog = models.ForeignKey(ChatHistory,on_delete=models.CASCADE,related_name='chatMessages')
    parts = models.TextField()
    role = models.TextField()
    def __str__(self):
        return self.message