from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.core.mail import EmailMessage
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.db.models import Q
from .models import Sale, SaleItem
from apps.inventory.models import Product, Inventory
from apps.customers.models import Customer, IrregularCustomer
from .utils import generate_receipt_pdf, number_to_words
from decimal import Decimal
import json
import logging
from apps.accounts.views import is_staff_level, log_change

logger = logging.getLogger(__name__)


def _redirect_no_tenant(request):
    try:
        if request.user.profile.role == 'superadmin':
            messages.error(request, 'Tenant access required for sales pages.')
            return redirect('superadmin_dashboard')
    except Exception:
        logger.debug("Unable to evaluate superadmin role in _redirect_no_tenant", exc_info=True)
    messages.error(request, 'Tenant access required. Please log in as a vendor.')
    return redirect('login')


def _get_tenant_db_or_redirect(request):
    tenant_db = getattr(request, 'tenant_db', None)
    if not tenant_db:
        return None
    return tenant_db

def _ensure_credit_transaction(sale, created_by=None, db_alias=None):
    if not sale.customer:
        return
    due_amount = sale.total_amount - sale.paid_amount
    if due_amount <= 0:
        return
    from apps.customers.models import CreditTransaction
    exists = CreditTransaction.objects.using(db_alias).filter(
        related_sale=sale,
        transaction_type='purchase'
    ).exists()
    if exists:
        return
    sale.customer.current_credit += due_amount
    sale.customer.save(using=db_alias)
    CreditTransaction.objects.using(db_alias).create(
        customer=sale.customer,
        transaction_type='purchase',
        amount=due_amount,
        balance_after=sale.customer.current_credit,
        related_sale=sale,
        description='Sale on credit',
        created_by=created_by,
    )

@login_required
def sales_home(request):
    return render(request, 'sales/sales_home.html')


@login_required
def pos_view(request):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    context = {
        'products': Product.objects.using(tenant_db).all(),
        'customers': Customer.objects.using(tenant_db).all(),
    }
    return render(request, 'sales/pos.html', context)

@login_required
@require_http_methods(["GET"])
def search_product_api(request):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return JsonResponse({'error': 'Tenant access required.'}, status=403)
    query = request.GET.get('q', '')
    if len(query) < 2:
        return JsonResponse({'products': []})
    
    products = Product.objects.using(tenant_db).filter(
        Q(product_name__icontains=query) |
        Q(barcode__icontains=query) |
        Q(sku__icontains=query)
    )[:10]
    
    results = []
    for product in products:
        results.append({
            'id': product.id,
            'name': product.product_name,
            'sku': product.sku,
            'barcode': product.barcode,
            'price': str(product.selling_price),
            'stock': product.current_stock,
        })
    
    return JsonResponse({'products': results})

@login_required
@require_http_methods(["GET"])
def get_customer_api(request):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return JsonResponse({'error': 'Tenant access required.'}, status=403)
    phone = request.GET.get('phone', '')
    try:
        customer = Customer.objects.using(tenant_db).get(
            Q(phone_number=phone) | Q(secondary_phone_number=phone)
        )
        return JsonResponse({
            'found': True,
            'name': customer.customer_name,
            'phone': customer.phone_number,
            'current_credit': str(customer.current_credit),
        })
    except Customer.DoesNotExist:
        return JsonResponse({'found': False})

@login_required
@require_http_methods(["POST"])
@transaction.atomic
def create_sale_api(request):
    try:
        tenant_db = _get_tenant_db_or_redirect(request)
        if not tenant_db:
            return JsonResponse({'success': False, 'error': 'Tenant access required.'}, status=403)
        data = json.loads(request.body)
        
        customer = None
        irregular_customer = None
        customer_type = data.get('customer_type', 'regular')
        if customer_type == 'irregular':
            irregular_customer = IrregularCustomer.objects.using(tenant_db).create(
                customer_name=data.get('ir_customer_name') or 'IR Customer',
                phone_number=data.get('ir_customer_phone', ''),
                address=data.get('ir_customer_address', ''),
            )
        elif data.get('customer_phone'):
            customer, _ = Customer.objects.using(tenant_db).get_or_create(
                phone_number=data['customer_phone'],
                defaults={'customer_name': data.get('customer_name', 'Walk-in Customer')}
            )
        
        payment_method = data.get('payment_method', 'cash')
        paid_amount = Decimal(str(data.get('paid_amount', 0)))
        total_amount = Decimal(str(data['total']))

        sale = Sale.objects.using(tenant_db).create(
            customer=customer,
            irregular_customer=irregular_customer,
            cashier=request.user.profile,
            subtotal=Decimal(str(data['subtotal'])),
            discount=Decimal(str(data.get('discount', 0))),
            discount_percent=Decimal(str(data.get('discount_percent', 0))),
            tax=Decimal(str(data['tax'])),
            total_amount=total_amount,
            payment_method=payment_method,
            payment_status='paid' if paid_amount >= total_amount else 'partial',
            paid_amount=paid_amount,
        )
        
        for item in data['items']:
            product = Product.objects.using(tenant_db).get(id=int(item['product_id']))
            SaleItem.objects.using(tenant_db).create(
                sale=sale,
                product=product,
                quantity=int(item['quantity']),
                unit_price=Decimal(str(item['price'])),
                discount_percent=Decimal(str(item.get('discount', 0))),
                line_total=Decimal(str(item['line_total'])),
            )
            
            inventory, _ = Inventory.objects.using(tenant_db).get_or_create(
                product=product,
                defaults={'quantity_in_stock': 0}
            )
            inventory.quantity_in_stock -= int(item['quantity'])
            inventory.save(using=tenant_db)
        
        _ensure_credit_transaction(sale, getattr(request.user, 'profile', None), db_alias=tenant_db)
        
        return JsonResponse({
            'success': True,
            'sale_number': sale.sale_number,
            'receipt_number': sale.receipt_number,
            'message': 'Sale created successfully'
        })
    
    except Exception as e:
        logger.exception("Error creating sale for tenant_db=%s: %s", tenant_db, e)
        return JsonResponse({
            'success': False,
            'error': 'An error occurred while processing the sale. Please try again.'
        }, status=400)

@login_required
def print_receipt(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    amount_in_words = number_to_words(sale.total_amount)
    change_due = max(sale.paid_amount - sale.total_amount, 0)
    return render(request, 'sales/receipt.html', {
        'sale': sale,
        'amount_in_words': amount_in_words,
        'change_due': change_due,
    })

@login_required
def receipt_pdf(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    buffer = generate_receipt_pdf(sale, tenant=getattr(request, 'tenant', None))
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    disposition = 'attachment' if request.GET.get('download') == '1' else 'inline'
    response['Content-Disposition'] = f'{disposition}; filename="receipt_{sale_number}.pdf"'
    return response

@login_required
def sales_list(request):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sales = Sale.objects.using(tenant_db).select_related('customer').all()
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    query = request.GET.get('q', '').strip()
    filter_by = request.GET.get('filter_by', 'customer')
    sort_by = request.GET.get('sort_by', 'date')
    
    if from_date:
        sales = sales.filter(sale_date__date__gte=from_date)
    if to_date:
        sales = sales.filter(sale_date__date__lte=to_date)

    if query:
        if filter_by == 'phone':
            sales = sales.filter(
                Q(customer__phone_number__icontains=query) |
                Q(irregular_customer__phone_number__icontains=query)
            )
        elif filter_by == 'sale_number':
            sales = sales.filter(sale_number__icontains=query)
        elif filter_by == 'amount':
            try:
                amount_value = float(query)
                sales = sales.filter(total_amount=amount_value)
            except ValueError:
                sales = sales.none()
        elif filter_by == 'payment_status':
            sales = sales.filter(payment_status__icontains=query)
        elif filter_by == 'order_status':
            sales = sales.filter(order_status__icontains=query)
        elif filter_by == 'all':
            sales = sales.filter(
                Q(sale_number__icontains=query) |
                Q(customer__customer_name__icontains=query) |
                Q(irregular_customer__customer_name__icontains=query) |
                Q(customer__phone_number__icontains=query) |
                Q(irregular_customer__phone_number__icontains=query) |
                Q(payment_status__icontains=query) |
                Q(order_status__icontains=query)
            )
        else:
            sales = sales.filter(
                Q(customer__customer_name__icontains=query) |
                Q(irregular_customer__customer_name__icontains=query)
            )

    if sort_by == 'customer_asc':
        sales = sales.order_by('customer__customer_name', 'irregular_customer__customer_name', '-sale_date')
    elif sort_by == 'customer_desc':
        sales = sales.order_by('-customer__customer_name', '-irregular_customer__customer_name', '-sale_date')
    elif sort_by == 'phone':
        sales = sales.order_by('customer__phone_number', 'irregular_customer__phone_number', '-sale_date')
    elif sort_by == 'amount_asc':
        sales = sales.order_by('total_amount', '-sale_date')
    elif sort_by == 'amount_desc':
        sales = sales.order_by('-total_amount', '-sale_date')
    elif sort_by == 'sale_number_asc':
        sales = sales.order_by('sale_number', '-sale_date')
    elif sort_by == 'sale_number_desc':
        sales = sales.order_by('-sale_number', '-sale_date')
    else:
        sales = sales.order_by('-sale_date')
    
    return render(request, 'sales/sales_list.html', {
        'sales': sales,
        'from_date': from_date,
        'to_date': to_date,
        'query': query,
        'filter_by': filter_by,
        'sort_by': sort_by,
    })


@login_required
def credit_records(request):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    customers = Customer.objects.using(tenant_db).filter(current_credit__gt=0)
    query = request.GET.get('q', '').strip()
    filter_by = request.GET.get('filter_by', 'name')
    sort_by = request.GET.get('sort_by', 'credit_desc')

    if query:
        if filter_by == 'phone':
            customers = customers.filter(
                Q(phone_number__icontains=query) |
                Q(secondary_phone_number__icontains=query)
            )
        elif filter_by == 'email':
            customers = customers.filter(email__icontains=query)
        elif filter_by == 'credit':
            try:
                credit_value = float(query)
                customers = customers.filter(current_credit=credit_value)
            except ValueError:
                customers = customers.none()
        elif filter_by == 'all':
            customers = customers.filter(
                Q(customer_name__icontains=query) |
                Q(phone_number__icontains=query) |
                Q(secondary_phone_number__icontains=query) |
                Q(email__icontains=query) |
                Q(city__icontains=query)
            )
        else:
            customers = customers.filter(customer_name__icontains=query)

    if sort_by == 'name_asc':
        customers = customers.order_by('customer_name')
    elif sort_by == 'name_desc':
        customers = customers.order_by('-customer_name')
    elif sort_by == 'credit_asc':
        customers = customers.order_by('current_credit', 'customer_name')
    else:
        customers = customers.order_by('-current_credit', 'customer_name')

    return render(request, 'sales/credit_records.html', {
        'customers': customers,
        'query': query,
        'filter_by': filter_by,
        'sort_by': sort_by,
    })

@login_required
def sales_detail(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    return render(request, 'sales/sales_detail.html', {'sale': sale})


@login_required
@transaction.atomic
def sales_return(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    if request.method == 'POST' and sale.order_status != 'returned':
        for item in sale.items.all():
            inventory, _ = Inventory.objects.using(tenant_db).get_or_create(
                product=item.product,
                defaults={'quantity_in_stock': 0}
            )
            inventory.quantity_in_stock += item.quantity
            inventory.save(using=tenant_db)

        if sale.customer:
            from apps.customers.models import CreditTransaction
            credit_change = 0
            if sale.payment_method == 'credit':
                credit_change = sale.total_amount
            elif sale.payment_status == 'partial':
                credit_change = sale.total_amount - sale.paid_amount
            if credit_change > 0:
                sale.customer.current_credit = max(sale.customer.current_credit - credit_change, 0)
                sale.customer.save(using=tenant_db)
                CreditTransaction.objects.using(tenant_db).create(
                    customer=sale.customer,
                    transaction_type='refund',
                    amount=credit_change,
                    balance_after=sale.customer.current_credit,
                    related_sale=sale,
                )

        sale.order_status = 'returned'
        sale.save(update_fields=['order_status'])
        messages.success(request, 'Sale marked as returned.')
        return redirect('sales_detail', sale_number=sale.sale_number)

    return render(request, 'sales/sales_return.html', {'sale': sale})


@login_required
@transaction.atomic
def sales_cancel(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    if request.method == 'POST' and sale.order_status != 'cancelled':
        for item in sale.items.all():
            inventory, _ = Inventory.objects.using(tenant_db).get_or_create(
                product=item.product,
                defaults={'quantity_in_stock': 0}
            )
            inventory.quantity_in_stock += item.quantity
            inventory.save(using=tenant_db)

        if sale.customer:
            from apps.customers.models import CreditTransaction
            credit_change = 0
            if sale.payment_method == 'credit':
                credit_change = sale.total_amount
            elif sale.payment_status == 'partial':
                credit_change = sale.total_amount - sale.paid_amount
            if credit_change > 0:
                sale.customer.current_credit = max(sale.customer.current_credit - credit_change, 0)
                sale.customer.save(using=tenant_db)
                CreditTransaction.objects.using(tenant_db).create(
                    customer=sale.customer,
                    transaction_type='refund',
                    amount=credit_change,
                    balance_after=sale.customer.current_credit,
                    related_sale=sale,
                )

        sale.order_status = 'cancelled'
        sale.save(update_fields=['order_status'])
        messages.success(request, 'Sale marked as cancelled.')
        return redirect('sales_detail', sale_number=sale.sale_number)

    return render(request, 'sales/sales_cancel.html', {'sale': sale})


@login_required
def sales_return_list(request):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sales = Sale.objects.using(tenant_db).filter(order_status='returned')
    query = request.GET.get('q', '').strip()
    filter_by = request.GET.get('filter_by', 'customer')
    sort_by = request.GET.get('sort_by', 'date_desc')

    if query:
        if filter_by == 'sale_number':
            sales = sales.filter(sale_number__icontains=query)
        elif filter_by == 'phone':
            sales = sales.filter(
                Q(customer__phone_number__icontains=query) |
                Q(irregular_customer__phone_number__icontains=query)
            )
        elif filter_by == 'amount':
            try:
                amount_value = float(query)
                sales = sales.filter(total_amount=amount_value)
            except ValueError:
                sales = sales.none()
        elif filter_by == 'payment_method':
            sales = sales.filter(payment_method__icontains=query)
        elif filter_by == 'all':
            sales = sales.filter(
                Q(sale_number__icontains=query) |
                Q(customer__customer_name__icontains=query) |
                Q(irregular_customer__customer_name__icontains=query) |
                Q(customer__phone_number__icontains=query) |
                Q(irregular_customer__phone_number__icontains=query) |
                Q(payment_method__icontains=query)
            )
        else:
            sales = sales.filter(
                Q(customer__customer_name__icontains=query) |
                Q(irregular_customer__customer_name__icontains=query)
            )

    if sort_by == 'date_asc':
        sales = sales.order_by('sale_date')
    elif sort_by == 'customer_asc':
        sales = sales.order_by('customer__customer_name', 'irregular_customer__customer_name', '-sale_date')
    elif sort_by == 'customer_desc':
        sales = sales.order_by('-customer__customer_name', '-irregular_customer__customer_name', '-sale_date')
    elif sort_by == 'amount_asc':
        sales = sales.order_by('total_amount', '-sale_date')
    elif sort_by == 'amount_desc':
        sales = sales.order_by('-total_amount', '-sale_date')
    else:
        sales = sales.order_by('-sale_date')

    return render(request, 'sales/returned_sales.html', {
        'sales': sales,
        'query': query,
        'filter_by': filter_by,
        'sort_by': sort_by,
    })


@login_required
def email_receipt(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    if not sale.customer or not sale.customer.email:
        messages.error(request, 'Customer email is not available for this sale.')
        return redirect('sales_detail', sale_number=sale.sale_number)

    pdf_buffer = generate_receipt_pdf(sale, tenant=getattr(request, 'tenant', None))
    email = EmailMessage(
        subject=f"Receipt {sale.receipt_number or sale.sale_number}",
        body="Please find your receipt attached. Thank you for your purchase!",
        to=[sale.customer.email],
    )
    email.attach(
        filename=f"receipt_{sale.sale_number}.pdf",
        content=pdf_buffer.getvalue(),
        mimetype='application/pdf',
    )

    try:
        email.send(fail_silently=False)
        messages.success(request, 'Receipt emailed to customer.')
    except Exception as exc:
        logger.exception("Failed to send receipt email for sale %s: %s", sale_number, exc)
        messages.error(request, "Unable to send email. Please try again or contact support.")

    return redirect('sales_detail', sale_number=sale.sale_number)

@login_required
def sales_edit(request, sale_number):
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    if request.method == 'POST':
        before = {
            'payment_method': sale.payment_method,
            'paid_amount': str(sale.paid_amount),
            'payment_status': sale.payment_status,
            'notes': sale.notes or '',
        }
        sale.payment_method = request.POST.get('payment_method', sale.payment_method)
        sale.paid_amount = Decimal(str(request.POST.get('paid_amount', sale.paid_amount)))
        sale.notes = request.POST.get('notes', '')
        sale.payment_status = 'paid' if sale.paid_amount >= sale.total_amount else 'partial'
        sale.save(using=tenant_db)
        after = {
            'payment_method': sale.payment_method,
            'paid_amount': str(sale.paid_amount),
            'payment_status': sale.payment_status,
            'notes': sale.notes or '',
        }
        _ensure_credit_transaction(sale, getattr(request.user, 'profile', None), db_alias=tenant_db)
        log_change(request, 'update', 'Sale', sale_number,
                   f'Updated payment for sale {sale_number}: method={sale.payment_method}, paid={sale.paid_amount}.',
                   before=before, after=after)
        messages.success(request, 'Sale updated successfully.')
        return redirect('sales_list')
    return render(request, 'sales/sales_edit.html', {'sale': sale})

@login_required
@transaction.atomic
def sales_delete(request, sale_number):
    if is_staff_level(request):
        messages.error(request, 'Staff users cannot delete records.')
        return redirect('sales_list')
    tenant_db = _get_tenant_db_or_redirect(request)
    if not tenant_db:
        return _redirect_no_tenant(request)
    sale = get_object_or_404(Sale.objects.using(tenant_db), sale_number=sale_number)
    if request.method == 'POST':
        for item in sale.items.all():
            inventory, _ = Inventory.objects.using(tenant_db).get_or_create(
                product=item.product,
                defaults={'quantity_in_stock': 0}
            )
            inventory.quantity_in_stock += item.quantity
            inventory.save(using=tenant_db)

        if sale.customer and sale.payment_method == 'credit':
            from apps.customers.models import CreditTransaction
            sale.customer.current_credit -= sale.total_amount
            sale.customer.save(using=tenant_db)
            CreditTransaction.objects.using(tenant_db).create(
                customer=sale.customer,
                transaction_type='refund',
                amount=sale.total_amount,
                balance_after=sale.customer.current_credit,
                related_sale=sale,
            )

        sale.delete()
        messages.success(request, 'Sale deleted successfully.')
        return redirect('sales_list')
    return render(request, 'sales/sales_delete.html', {'sale': sale})
