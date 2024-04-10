from django.urls import path
from .views import SignUp,Login,LogOut

urlpatterns = [
    path('signup/',SignUp.as_view(),name='sign_up'),
    path('login/',Login.as_view(),name='log_in'),
    path('logout/',LogOut.as_view(),name='log_out')
]