from django.urls import path
from .views import PromptGemini,testChatHistory
urlpatterns = [
    path('prompt/',PromptGemini.as_view(),name='get_prompt'),
    path('test/',testChatHistory,name='test_chat')
]