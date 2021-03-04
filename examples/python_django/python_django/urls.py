from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('didkit/', include('didkit_django.urls')),
    path('admin/', admin.site.urls),
]
