from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView

urlpatterns = [
    path('', RedirectView.as_view(url='accounts/login/', permanent=False)),
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

