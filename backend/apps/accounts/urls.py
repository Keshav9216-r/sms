from django.urls import path
from . import views

urlpatterns = [
	path('login/', views.login_view, name='login'),
	path('admin/', views.superadmin_login_view, name='superadmin_login'),
	path('vendor-login/', views.vendor_login_view, name='vendor_login'),
	path('user-login/', views.user_login_view, name='user_login'),
	path('logout/', views.logout_view, name='logout'),
	path('', views.dashboard, name='dashboard'),
	path('profile/', views.profile, name='profile'),
	path('change-password/', views.change_password, name='change_password'),
	path('users/', views.manage_users, name='manage_users'),
	path('users/create/', views.create_user, name='create_user'),
	path('users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
]


