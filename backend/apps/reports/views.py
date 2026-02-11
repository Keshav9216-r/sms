from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.db.models import Sum, F, Q
from django.utils import timezone
from apps.sales.models import Sale
from apps.inventory.models import Product, Inventory
from apps.customers.models import Customer
from apps.tenants.models import Tenant

@login_required
def reports_dashboard(request):
    is_superadmin = False
    try:
        is_superadmin = request.user.profile.role == 'superadmin'
    except Exception:
        is_superadmin = False

    if is_superadmin:
        vendors = Tenant.objects.using('default').all().order_by('-created_at')
        total_vendors = vendors.count()
        active_vendors = vendors.filter(is_active=True).count()
        inactive_vendors = vendors.filter(is_active=False).count()
        return render(request, 'reports/dashboard.html', {
            'is_superadmin': True,
            'vendors': vendors,
            'total_vendors': total_vendors,
            'active_vendors': active_vendors,
            'inactive_vendors': inactive_vendors,
        })

    total_products = Product.objects.count()
    total_customers = Customer.objects.count()
    today = timezone.localdate()
    today_sales = (
        Sale.objects.filter(sale_date__date=today)
        .aggregate(total=Sum('total_amount'))['total']
        or 0
    )
    low_stock_count = Inventory.objects.filter(
        quantity_in_stock__lte=F('product__reorder_level')
    ).count()

    return render(request, 'reports/dashboard.html', {
        'is_superadmin': False,
        'total_products': total_products,
        'today_sales': today_sales,
        'total_customers': total_customers,
        'low_stock_count': low_stock_count,
    })

@login_required
def low_stock_report(request):
    query = request.GET.get('q', '').strip()
    search_by = request.GET.get('search_by', 'name')
    sort_by = request.GET.get('sort_by', 'stock_asc')

    low_stock_qs = Inventory.objects.select_related('product', 'product__category').filter(
        quantity_in_stock__lte=F('product__reorder_level')
    )

    if query:
        if search_by == 'sku':
            low_stock_qs = low_stock_qs.filter(product__sku__icontains=query)
        elif search_by == 'barcode':
            low_stock_qs = low_stock_qs.filter(product__barcode__icontains=query)
        elif search_by == 'category':
            low_stock_qs = low_stock_qs.filter(product__category__name__icontains=query)
        elif search_by == 'all':
            low_stock_qs = low_stock_qs.filter(
                Q(product__product_name__icontains=query) |
                Q(product__sku__icontains=query) |
                Q(product__barcode__icontains=query) |
                Q(product__category__name__icontains=query)
            )
        else:
            low_stock_qs = low_stock_qs.filter(product__product_name__icontains=query)

    sort_map = {
        'stock_asc': 'quantity_in_stock',
        'stock_desc': '-quantity_in_stock',
        'reorder_asc': 'product__reorder_level',
        'reorder_desc': '-product__reorder_level',
        'name': 'product__product_name',
    }
    low_stock_qs = low_stock_qs.order_by(sort_map.get(sort_by, 'quantity_in_stock'))

    return render(request, 'reports/low_stock.html', {
        'low_stock_items': low_stock_qs,
        'query': query,
        'search_by': search_by,
        'sort_by': sort_by,
    })

@login_required
def sales_report(request):
    sales = Sale.objects.all()
    total_sales = sales.aggregate(Sum('total_amount'))['total_amount__sum'] or 0
    sale_count = sales.count()
    return render(request, 'reports/sales_report.html', {
        'sales': sales,
        'total_sales': total_sales,
        'sale_count': sale_count
    })

@login_required
def today_sales_report(request):
    today = timezone.localdate()
    sales = Sale.objects.select_related('customer', 'irregular_customer').filter(
        sale_date__date=today
    ).order_by('-sale_date')
    total_sales = sales.aggregate(Sum('total_amount'))['total_amount__sum'] or 0
    return render(request, 'reports/today_sales.html', {
        'sales': sales,
        'total_sales': total_sales,
        'today': today,
    })

@login_required
def inventory_report(request):
    products = Product.objects.all()
    return render(request, 'reports/inventory_report.html', {'products': products})

@login_required
def customer_report(request):
    customers = Customer.objects.all()
    return render(request, 'reports/customer_report.html', {'customers': customers})

@login_required
def export_sales(request):
    return HttpResponse("Export sales - Coming soon", content_type='text/plain')

@login_required
def export_inventory(request):
    return HttpResponse("Export inventory - Coming soon", content_type='text/plain')
