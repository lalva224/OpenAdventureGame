from django.urls import path
from .views import PromptGemini,Start,End_Game
urlpatterns = [
    path('prompt/',PromptGemini.as_view(),name='get_prompt'),
    path('start/',Start.as_view(),name='start_new_game'),
    path('endgame/',End_Game.as_view(),name='end_game')
]