from django.urls import path
from . import views

urlpatterns = [
    # Customer URLs
    path('', views.customer_list, name='customer_list'),
    path('add/', views.customer_add, name='customer_add'),
    path('ir/<int:pk>/', views.irregular_customer_detail, name='irregular_customer_detail'),
    path('<str:phone>/', views.customer_detail, name='customer_detail'),
    path('<str:phone>/edit/', views.customer_edit, name='customer_edit'),
    path('<str:phone>/delete/', views.customer_delete, name='customer_delete'),
    path('<str:phone>/credit/', views.customer_credit_history, name='customer_credit_history'),
    path('<str:phone>/pay/', views.customer_pay_credit, name='customer_pay_credit'),
    path('credit/receipt/<int:tx_id>/', views.customer_payment_receipt, name='customer_payment_receipt'),
]
