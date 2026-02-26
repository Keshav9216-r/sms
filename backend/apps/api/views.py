import logging
from decimal import Decimal

from django.db import transaction
from django.db.models import F, Sum
from django.utils import timezone
from rest_framework import permissions, viewsets, status
from rest_framework.response import Response

from apps.accounts.models import UserProfile
from apps.customers.models import Customer, CreditTransaction, IrregularCustomer
from apps.inventory.models import Category, Product, Inventory
from apps.sales.models import Sale, SaleItem
from apps.tenants.models import Tenant

from .serializers import (
    TenantSerializer,
    CategorySerializer,
    ProductSerializer,
    InventorySerializer,
    CustomerSerializer,
    CreditTransactionSerializer,
    IrregularCustomerSerializer,
    SaleSerializer,
    SaleItemSerializer,
    TenantUserSerializer,
)

logger = logging.getLogger('security')


class IsSuperAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        try:
            return request.user.profile.role == 'superadmin'
        except UserProfile.DoesNotExist:
            return False


class IsTenantManager(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        try:
            return request.user.profile.role in {'superadmin', 'tenant_admin', 'manager'}
        except UserProfile.DoesNotExist:
            return False


def _get_tenant_db(request):
    """Return the tenant DB alias for the current request, or None."""
    return getattr(request, 'tenant_db', None)


class TenantViewSet(viewsets.ModelViewSet):
    queryset = Tenant.objects.using('default').all()
    serializer_class = TenantSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]


class CategoryViewSet(viewsets.ModelViewSet):
    serializer_class = CategorySerializer

    def get_permissions(self):
        if self.request.method in ('GET', 'HEAD', 'OPTIONS'):
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), IsTenantManager()]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return Category.objects.none()
        return Category.objects.using(tenant_db).all()


class ProductViewSet(viewsets.ModelViewSet):
    serializer_class = ProductSerializer

    def get_permissions(self):
        if self.request.method in ('GET', 'HEAD', 'OPTIONS'):
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), IsTenantManager()]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return Product.objects.none()
        return Product.objects.using(tenant_db).all()


class InventoryViewSet(viewsets.ModelViewSet):
    serializer_class = InventorySerializer

    def get_permissions(self):
        if self.request.method in ('GET', 'HEAD', 'OPTIONS'):
            return [permissions.IsAuthenticated()]
        return [permissions.IsAuthenticated(), IsTenantManager()]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return Inventory.objects.none()
        return Inventory.objects.using(tenant_db).select_related('product').all()


class CustomerViewSet(viewsets.ModelViewSet):
    serializer_class = CustomerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return Customer.objects.none()
        return Customer.objects.using(tenant_db).all()


class IrregularCustomerViewSet(viewsets.ModelViewSet):
    serializer_class = IrregularCustomerSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return IrregularCustomer.objects.none()
        return IrregularCustomer.objects.using(tenant_db).all()


class CreditTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = CreditTransactionSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return CreditTransaction.objects.none()
        return CreditTransaction.objects.using(tenant_db).select_related('customer').all()


class SaleViewSet(viewsets.ModelViewSet):
    serializer_class = SaleSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return Sale.objects.none()
        return Sale.objects.using(tenant_db).select_related('customer', 'cashier').prefetch_related('items').all()

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        tenant_db = _get_tenant_db(request)
        if not tenant_db:
            return Response({'detail': 'Tenant context required.'}, status=status.HTTP_403_FORBIDDEN)

        data = request.data
        items = data.get('items', [])
        if not items:
            return Response({'detail': 'Sale items are required.'}, status=status.HTTP_400_BAD_REQUEST)

        customer = None
        irregular_customer = None
        customer_type = data.get('customer_type', 'regular')
        customer_phone = data.get('customer_phone')

        if customer_type == 'irregular':
            irregular_customer = IrregularCustomer.objects.using(tenant_db).create(
                customer_name=data.get('ir_customer_name') or 'IR Customer',
                phone_number=data.get('ir_customer_phone', ''),
                address=data.get('ir_customer_address', ''),
            )
        elif customer_phone:
            customer, _ = Customer.objects.using(tenant_db).get_or_create(
                phone_number=customer_phone,
                defaults={'customer_name': data.get('customer_name', 'Walk-in Customer')},
            )

        paid_amount = Decimal(str(data.get('paid_amount', 0)))
        total_amount = Decimal(str(data.get('total_amount', data.get('total', 0))))

        sale = Sale.objects.using(tenant_db).create(
            customer=customer,
            irregular_customer=irregular_customer,
            cashier=request.user.profile if hasattr(request.user, 'profile') else None,
            subtotal=Decimal(str(data.get('subtotal', 0))),
            discount=Decimal(str(data.get('discount', 0))),
            discount_percent=Decimal(str(data.get('discount_percent', 0))),
            tax=Decimal(str(data.get('tax', 0))),
            total_amount=total_amount,
            payment_method=data.get('payment_method', 'cash'),
            payment_status='paid' if paid_amount >= total_amount else 'partial',
            paid_amount=paid_amount,
            notes=data.get('notes', ''),
        )

        for item in items:
            try:
                product = Product.objects.using(tenant_db).get(id=int(item['product']))
            except (Product.DoesNotExist, KeyError, ValueError):
                return Response(
                    {'detail': f"Product id={item.get('product')} not found in this tenant."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            quantity = int(item['quantity'])
            unit_price = Decimal(str(item.get('unit_price', item.get('price', 0))))
            discount_percent = Decimal(str(item.get('discount_percent', item.get('discount', 0))))
            line_total = Decimal(str(item.get('line_total', unit_price * quantity)))

            SaleItem.objects.using(tenant_db).create(
                sale=sale,
                product=product,
                quantity=quantity,
                unit_price=unit_price,
                discount_percent=discount_percent,
                line_total=line_total,
            )

            inventory, _ = Inventory.objects.using(tenant_db).get_or_create(
                product=product,
                defaults={'quantity_in_stock': 0},
            )
            inventory.quantity_in_stock = F('quantity_in_stock') - quantity
            inventory.save(using=tenant_db)

        self._ensure_credit_transaction(sale, tenant_db)
        serializer = self.get_serializer(sale)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @staticmethod
    def _ensure_credit_transaction(sale, tenant_db):
        if not sale.customer:
            return
        due_amount = sale.total_amount - sale.paid_amount
        if due_amount <= 0:
            return
        if CreditTransaction.objects.using(tenant_db).filter(related_sale=sale, transaction_type='purchase').exists():
            return
        sale.customer.current_credit += due_amount
        sale.customer.save(using=tenant_db)
        CreditTransaction.objects.using(tenant_db).create(
            customer=sale.customer,
            transaction_type='purchase',
            amount=due_amount,
            balance_after=sale.customer.current_credit,
            related_sale=sale,
            description='Sale on credit',
            created_by=sale.cashier,
        )


class SaleItemViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = SaleItemSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return SaleItem.objects.none()
        return SaleItem.objects.using(tenant_db).select_related('sale', 'product').all()


class ReportsViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        tenant_db = _get_tenant_db(request)
        if not tenant_db:
            return Response({'detail': 'Tenant context required.'}, status=status.HTTP_403_FORBIDDEN)

        today = timezone.localdate()
        total_products = Product.objects.using(tenant_db).count()
        total_customers = Customer.objects.using(tenant_db).count()
        today_sales_total = (
            Sale.objects.using(tenant_db)
            .filter(sale_date__date=today)
            .aggregate(total=Sum('total_amount'))['total']
            or 0
        )
        low_stock_count = Inventory.objects.using(tenant_db).filter(
            quantity_in_stock__lte=F('product__reorder_level')
        ).count()

        return Response({
            'total_products': total_products,
            'total_customers': total_customers,
            'today_sales': str(today_sales_total),
            'low_stock_count': low_stock_count,
        })


class TenantUserViewSet(viewsets.ModelViewSet):
    serializer_class = TenantUserSerializer
    permission_classes = [permissions.IsAuthenticated, IsTenantManager]

    def get_queryset(self):
        tenant_db = _get_tenant_db(self.request)
        if not tenant_db:
            return UserProfile.objects.none()
        return UserProfile.objects.using(tenant_db).all()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['tenant'] = getattr(self.request, 'tenant', None)
        context['db_alias'] = getattr(self.request, 'tenant_db', None)
        return context

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        profile = serializer.save()
        logger.info(
            "User '%s' created by '%s' in tenant '%s'",
            profile.user.username,
            request.user.username,
            getattr(request.tenant, 'code', 'unknown'),
        )
        return Response(TenantUserSerializer(profile).data, status=status.HTTP_201_CREATED)
