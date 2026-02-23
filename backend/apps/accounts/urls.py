from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('admin/', views.superadmin_login_view, name='superadmin_login'),
    path('vendor-login/', views.vendor_login_view, name='vendor_login'),
    path('user-login/', views.staff_login_view, name='user_login'),
    path('logout/', views.logout_view, name='logout'),
    path('', views.dashboard, name='dashboard'),
    path('profile/', views.profile, name='profile'),
    path('change-password/', views.change_password, name='change_password'),
    # Staff management
    path('staff/', views.staff_list, name='staff_list'),
    path('staff/create/', views.staff_create, name='staff_create'),
    path('staff/<int:user_id>/edit/', views.staff_edit, name='staff_edit'),
    path('staff/<int:user_id>/delete/', views.staff_delete, name='staff_delete'),
    # Changelog
    path('changelog/', views.changelog_list, name='changelog_list'),
]
