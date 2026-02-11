from django.urls import path
from . import views

urlpatterns = [
    path('', views.product_list, name='inventory_home'),
    # Product URLs
    path('products/', views.product_list, name='product_list'),
    path('products/books/', views.product_list_books, name='product_list_books'),
    path('products/stationery/', views.product_list_stationery, name='product_list_stationery'),
    path('products/add/', views.product_add, name='product_add'),
    path('products/<int:pk>/edit/', views.product_edit, name='product_edit'),
    path('products/<int:pk>/delete/', views.product_delete, name='product_delete'),
    
    # Category URLs
    path('categories/', views.category_list, name='category_list'),
    path('categories/add/', views.category_add, name='category_add'),
    path('categories/<int:category_id>/edit/', views.category_edit, name='category_edit'),
    path('categories/<int:category_id>/delete/', views.category_delete, name='category_delete'),
    
    # Inventory URLs
    path('inventory/', views.inventory_list, name='inventory_list'),
    path('inventory/<int:pk>/', views.inventory_detail, name='inventory_detail'),
    path('inventory/<int:pk>/adjust/', views.stock_adjust, name='stock_adjust'),
    
    # Barcode
    path('barcode/<int:product_id>/', views.generate_barcode, name='generate_barcode'),
]
