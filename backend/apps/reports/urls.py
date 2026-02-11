from django.urls import path
from . import views

urlpatterns = [
    path('', views.reports_dashboard, name='reports_dashboard'),
    path('low-stock/', views.low_stock_report, name='low_stock_report'),
    path('sales/', views.sales_report, name='sales_report'),
    path('sales/today/', views.today_sales_report, name='today_sales_report'),
    path('inventory/', views.inventory_report, name='inventory_report'),
    path('customers/', views.customer_report, name='customer_report'),
    
    # Export
    path('sales/export/', views.export_sales, name='export_sales'),
    path('inventory/export/', views.export_inventory, name='export_inventory'),
]
