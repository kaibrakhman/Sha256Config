from django.urls import path
from .views import md55,index,base644,base644decode

urlpatterns = [
    path('', index,name="index"),
    path('md5/', md55,name="md5"),
    path('base64/', base644,name="base64"),
    path('decoderbase64/', base644decode,name="base64decode"),
]