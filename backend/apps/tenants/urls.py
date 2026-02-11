from django.urls import path
from . import views

urlpatterns = [
    # Superadmin paths
    path('superadmin/dashboard/', views.superadmin_dashboard, name='superadmin_dashboard'),
    path('superadmin/create-vendor/', views.create_vendor, name='create_vendor'),
    path('superadmin/vendor/<int:tenant_id>/', views.vendor_detail, name='vendor_detail'),
    path('superadmin/vendor/<int:tenant_id>/deactivate/', views.deactivate_vendor, name='deactivate_vendor'),
    path('superadmin/vendor/<int:tenant_id>/activate/', views.activate_vendor, name='activate_vendor'),
    path('superadmin/vendor/<int:tenant_id>/reset-password/', views.reset_vendor_password, name='reset_vendor_password'),
    path('superadmin/vendor/<int:tenant_id>/login-as/', views.superadmin_login_as_vendor, name='superadmin_login_as_vendor'),
    path('superadmin/change-password/', views.superadmin_change_password, name='superadmin_change_password'),
    path('superadmin/vendor/<int:tenant_id>/delete/', views.delete_vendor, name='delete_vendor'),
]
