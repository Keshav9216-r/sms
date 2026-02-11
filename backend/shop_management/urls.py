from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.http import JsonResponse


def health_check(request):
    return JsonResponse({'status': 'ok'})

urlpatterns = [
    path('', RedirectView.as_view(url='accounts/login/', permanent=False)),
    path('health/', health_check, name='health_check'),
    path('accounts/', include('apps.accounts.urls')),
    path('tenants/', include('apps.tenants.urls')),
    path('api/', include('apps.api.urls')),
    path('inventory/', include('apps.inventory.urls')),
    path('customers/', include('apps.customers.urls')),
    path('sales/', include('apps.sales.urls')),
    path('reports/', include('apps.reports.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

