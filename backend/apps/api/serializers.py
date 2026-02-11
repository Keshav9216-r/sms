from django.contrib.auth import get_user_model
from rest_framework import serializers
from apps.accounts.models import UserProfile
from apps.customers.models import Customer, CreditTransaction, IrregularCustomer
from apps.inventory.models import Category, Product, Inventory
from apps.sales.models import Sale, SaleItem
from apps.tenants.models import Tenant


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = [
            'id',
            'name',
            'vendor_person_name',
            'pan_number',
            'vendor_phone',
            'code',
            'owner_email',
            'db_name',
            'access_customers',
            'access_inventory',
            'access_sales',
            'access_reports',
            'status',
            'is_active',
            'created_at',
            'updated_at',
        ]


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'


class ProductSerializer(serializers.ModelSerializer):
    category_name = serializers.CharField(source='category.name', read_only=True)
    current_stock = serializers.IntegerField(read_only=True)

    class Meta:
        model = Product
        fields = [
            'id',
            'sku',
            'barcode',
            'product_name',
            'category',
            'category_name',
            'description',
            'supplier',
            'book_name',
            'book_class',
            'book_publication',
            'image',
            'cost_price',
            'selling_price',
            'wholesale_price',
            'reorder_level',
            'unit',
            'is_active',
            'created_date',
            'updated_date',
            'current_stock',
        ]


class InventorySerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.product_name', read_only=True)
    available_stock = serializers.IntegerField(read_only=True)
    low_stock_alert = serializers.BooleanField(read_only=True)

    class Meta:
        model = Inventory
        fields = [
            'id',
            'product',
            'product_name',
            'quantity_in_stock',
            'quantity_reserved',
            'last_restock_date',
            'last_counted_date',
            'updated_date',
            'available_stock',
            'low_stock_alert',
        ]


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'


class IrregularCustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = IrregularCustomer
        fields = '__all__'


class CreditTransactionSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='customer.customer_name', read_only=True)

    class Meta:
        model = CreditTransaction
        fields = '__all__'
        read_only_fields = ('customer_name',)


class SaleItemSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.product_name', read_only=True)

    class Meta:
        model = SaleItem
        fields = [
            'id',
            'product',
            'product_name',
            'quantity',
            'unit_price',
            'discount_percent',
            'line_total',
        ]


class SaleSerializer(serializers.ModelSerializer):
    items = SaleItemSerializer(many=True, read_only=True)
    customer_name = serializers.CharField(source='customer.customer_name', read_only=True)

    class Meta:
        model = Sale
        fields = [
            'id',
            'sale_number',
            'receipt_number',
            'customer',
            'customer_name',
            'irregular_customer',
            'cashier',
            'sale_date',
            'subtotal',
            'discount',
            'discount_percent',
            'tax',
            'total_amount',
            'payment_method',
            'payment_status',
            'paid_amount',
            'order_status',
            'notes',
            'is_printed',
            'items',
        ]
        read_only_fields = ('sale_number', 'receipt_number', 'sale_date')


class TenantUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(write_only=True)
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True)
    role = serializers.ChoiceField(choices=UserProfile.ROLE_CHOICES)

    class Meta:
        model = UserProfile
        fields = ['id', 'username', 'email', 'password', 'role', 'phone', 'address', 'city', 'is_active']

    def validate_role(self, value):
        tenant = self.context.get('tenant')
        if tenant and value == 'superadmin':
            raise serializers.ValidationError('Superadmin role is not allowed for tenant users.')
        return value

    def create(self, validated_data):
        UserModel = get_user_model()
        db_alias = self.context.get('db_alias')
        tenant = self.context.get('tenant')
        username = validated_data.pop('username')
        email = validated_data.pop('email')
        password = validated_data.pop('password')
        role = validated_data.pop('role')

        if db_alias:
            user = UserModel.objects.db_manager(db_alias).create_user(
                username=username,
                email=email,
                password=password,
                is_staff=role in {'tenant_admin', 'manager'},
            )
            profile = UserProfile.objects.using(db_alias).create(
                user=user,
                role=role,
                tenant_id=getattr(tenant, 'id', None),
                **validated_data,
            )
            return profile

        user = UserModel.objects.create_user(
            username=username,
            email=email,
            password=password,
            is_staff=role in {'tenant_admin', 'manager'},
        )
        profile = UserProfile.objects.create(
            user=user,
            role=role,
            tenant=tenant,
            **validated_data,
        )
        return profile
