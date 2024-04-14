from django.urls import path
from .views import PromptGemini,Start,End_Game,get_Image,create_download_copy
urlpatterns = [
    path('prompt/',PromptGemini.as_view(),name='get_prompt'),
    path('start/',Start.as_view(),name='start_new_game'),
    path('endgame/',End_Game.as_view(),name='end_game'),
    path('image/',get_Image.as_view(),name='get_image'),
    path('download/',create_download_copy.as_view())
]