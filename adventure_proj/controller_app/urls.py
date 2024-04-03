from django.urls import path
from .views import PromptGemini
urlpatterns = [
    path('prompt/',PromptGemini.as_view(),name='get_prompt')
]