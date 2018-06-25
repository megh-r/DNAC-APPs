from . import views
from django.conf.urls import url


urlpatterns = [
    url(r'^index/$', views.index, name='index'),
    url(r'^ajax/validate_username/$', views.validate_username, name='validate_username'),
    url(r'^associateProject/$', views.associateProject, name='associateProject'),
    url(r'^disassociateProject/$', views.disassociateProject, name='disassociateProject'),
    url(r'^refreshProject/$', views.refreshProject, name='refreshProject'),
    url(r'^multipleOUs/$', views.multipleOUs, name='multipleOUs'),
]
handler404 = 'project.views.handler404'
handler500 = 'project.views.handler500'
