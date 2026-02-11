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
from apps.tenants.utils import get_current_tenant_db

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


class RequireTenant(permissions.BasePermission):
    def has_permission(self, request, view):
        return bool(get_current_tenant_db())


class TenantViewSet(viewsets.ModelViewSet):
    queryset = Tenant.objects.using('default').all()
    serializer_class = TenantSerializer
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]


class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class InventoryViewSet(viewsets.ModelViewSet):
    queryset = Inventory.objects.select_related('product').all()
    serializer_class = InventorySerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class IrregularCustomerViewSet(viewsets.ModelViewSet):
    queryset = IrregularCustomer.objects.all()
    serializer_class = IrregularCustomerSerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class CreditTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = CreditTransaction.objects.select_related('customer').all()
    serializer_class = CreditTransactionSerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class SaleViewSet(viewsets.ModelViewSet):
    queryset = Sale.objects.select_related('customer', 'cashier').prefetch_related('items').all()
    serializer_class = SaleSerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        data = request.data
        items = data.get('items', [])
        if not items:
            return Response({'detail': 'Sale items are required.'}, status=status.HTTP_400_BAD_REQUEST)

        locked_inventory = {}
        for item in items:
            product_id = int(item['product'])
            quantity = int(item['quantity'])
            if quantity <= 0:
                return Response({'detail': 'Item quantity must be positive.'}, status=status.HTTP_400_BAD_REQUEST)
            if product_id not in locked_inventory:
                product = Product.objects.get(id=product_id)
                inventory = Inventory.objects.select_for_update().filter(product=product).first()
                if not inventory:
                    inventory = Inventory.objects.create(product=product, quantity_in_stock=0)
                locked_inventory[product_id] = inventory
            inventory = locked_inventory[product_id]
            if inventory.quantity_in_stock < quantity:
                return Response(
                    {'detail': f'Insufficient stock for {inventory.product.product_name}.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        customer = None
        irregular_customer = None
        customer_type = data.get('customer_type', 'regular')
        customer_phone = data.get('customer_phone')

        if customer_type == 'irregular':
            irregular_customer = IrregularCustomer.objects.create(
                customer_name=data.get('ir_customer_name') or 'IR Customer',
                phone_number=data.get('ir_customer_phone', ''),
                address=data.get('ir_customer_address', ''),
            )
        elif customer_phone:
            customer, _ = Customer.objects.get_or_create(
                phone_number=customer_phone,
                defaults={'customer_name': data.get('customer_name', 'Walk-in Customer')},
            )

        paid_amount = Decimal(str(data.get('paid_amount', 0)))
        total_amount = Decimal(str(data.get('total_amount', data.get('total', 0))))

        sale = Sale.objects.create(
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
            product = Product.objects.get(id=int(item['product']))
            quantity = int(item['quantity'])
            unit_price = Decimal(str(item.get('unit_price', item.get('price', 0))))
            discount_percent = Decimal(str(item.get('discount_percent', item.get('discount', 0))))
            line_total = Decimal(str(item.get('line_total', unit_price * quantity)))

            SaleItem.objects.create(
                sale=sale,
                product=product,
                quantity=quantity,
                unit_price=unit_price,
                discount_percent=discount_percent,
                line_total=line_total,
            )

            inventory = locked_inventory[product.id]
            inventory.quantity_in_stock = F('quantity_in_stock') - quantity
            inventory.save()

        self._ensure_credit_transaction(sale)
        serializer = self.get_serializer(sale)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @staticmethod
    def _ensure_credit_transaction(sale):
        if not sale.customer:
            return
        due_amount = sale.total_amount - sale.paid_amount
        if due_amount <= 0:
            return
        if CreditTransaction.objects.filter(related_sale=sale, transaction_type='purchase').exists():
            return
        sale.customer.current_credit += due_amount
        sale.customer.save()
        CreditTransaction.objects.create(
            customer=sale.customer,
            transaction_type='purchase',
            amount=due_amount,
            balance_after=sale.customer.current_credit,
            related_sale=sale,
            description='Sale on credit',
            created_by=sale.cashier,
        )


class SaleItemViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = SaleItem.objects.select_related('sale', 'product').all()
    serializer_class = SaleItemSerializer
    permission_classes = [permissions.IsAuthenticated, RequireTenant]


class ReportsViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated, RequireTenant]

    def list(self, request):
        today = timezone.localdate()
        total_products = Product.objects.count()
        total_customers = Customer.objects.count()
        today_sales_total = (
            Sale.objects.filter(sale_date__date=today)
            .aggregate(total=Sum('total_amount'))['total']
            or 0
        )
        low_stock_count = Inventory.objects.filter(
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
    permission_classes = [permissions.IsAuthenticated, RequireTenant, IsTenantManager]

    def get_queryset(self):
        return UserProfile.objects.all()

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['tenant'] = getattr(self.request, 'tenant', None)
        context['db_alias'] = getattr(self.request, 'tenant_db', None)
        return context

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        profile = serializer.save()
        return Response(TenantUserSerializer(profile).data, status=status.HTTP_201_CREATED)
