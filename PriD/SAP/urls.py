from django.conf.urls import url
from . import views


urlpatterns = [
    url(r'^index/$', views.index, name='index'),
    url(r'^permit/$', views.permit, name='permit'),
    url(r'^revoke/$', views.revoke, name='revoke'),

]
