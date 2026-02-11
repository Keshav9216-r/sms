from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    TenantViewSet,
    CategoryViewSet,
    ProductViewSet,
    InventoryViewSet,
    CustomerViewSet,
    IrregularCustomerViewSet,
    CreditTransactionViewSet,
    SaleViewSet,
    SaleItemViewSet,
    ReportsViewSet,
    TenantUserViewSet,
)

router = DefaultRouter()
router.register('tenants', TenantViewSet, basename='tenant')
router.register('categories', CategoryViewSet, basename='category')
router.register('products', ProductViewSet, basename='product')
router.register('inventory', InventoryViewSet, basename='inventory')
router.register('customers', CustomerViewSet, basename='customer')
router.register('irregular-customers', IrregularCustomerViewSet, basename='irregular-customer')
router.register('credit-transactions', CreditTransactionViewSet, basename='credit-transaction')
router.register('sales', SaleViewSet, basename='sale')
router.register('sale-items', SaleItemViewSet, basename='sale-item')
router.register('reports', ReportsViewSet, basename='reports')
router.register('tenant-users', TenantUserViewSet, basename='tenant-user')

urlpatterns = [
    path('', include(router.urls)),
]
