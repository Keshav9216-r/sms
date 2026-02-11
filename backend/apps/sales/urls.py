from django.urls import path
from . import views

urlpatterns = [
    path('', views.sales_home, name='sales_home'),
    # POS & Billing
    path('pos/', views.pos_view, name='pos'),
    path('api/search-product/', views.search_product_api, name='search_product_api'),
    path('api/get-customer/', views.get_customer_api, name='get_customer_api'),
    path('api/create-sale/', views.create_sale_api, name='create_sale_api'),
    
    # Receipt & Invoice
    path('receipt/<str:sale_number>/', views.print_receipt, name='print_receipt'),
    path('receipt/<str:sale_number>/pdf/', views.receipt_pdf, name='receipt_pdf'),
    
    # Sales History
    path('history/', views.sales_list, name='sales_list'),
    path('credits/', views.credit_records, name='credit_records'),
    path('returns/', views.sales_return_list, name='sales_return_list'),
    path('return/<str:sale_number>/', views.sales_return, name='sales_return'),
    path('cancel/<str:sale_number>/', views.sales_cancel, name='sales_cancel'),
    path('email/<str:sale_number>/', views.email_receipt, name='email_receipt'),
    path('edit/<str:sale_number>/', views.sales_edit, name='sales_edit'),
    path('delete/<str:sale_number>/', views.sales_delete, name='sales_delete'),
    path('<str:sale_number>/', views.sales_detail, name='sales_detail'),
]
