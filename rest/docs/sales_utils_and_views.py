# sales/utils.py - PDF Receipt & Utility Functions

from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from io import BytesIO
from datetime import datetime
from django.conf import settings
import barcode
from barcode.writer import ImageWriter

def generate_receipt_pdf(sale):
    """Generate PDF receipt for a sale"""
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=(3.5*inch, 8*inch), topMargin=0.2*inch, bottomMargin=0.2*inch)
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Shop Header
    shop_name = Paragraph('<b>SHOP NAME</b>', ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=14))
    shop_address = Paragraph('Kathmandu, Nepal', ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=8))
    shop_phone = Paragraph('Ph: +977-1-XXXXXXX', ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=8))
    
    elements.append(shop_name)
    elements.append(shop_address)
    elements.append(shop_phone)
    elements.append(Spacer(1, 0.1*inch))
    
    # Sale Info
    sale_info = f"Receipt No: {sale.sale_number}\nDate: {sale.sale_date.strftime('%Y-%m-%d %H:%M')}"
    if sale.customer:
        sale_info += f"\nCustomer: {sale.customer.customer_name}"
    
    elements.append(Paragraph(sale_info, ParagraphStyle(name='left', alignment=TA_LEFT, fontSize=8)))
    elements.append(Spacer(1, 0.1*inch))
    
    # Items Table
    data = [['Item', 'Qty', 'Rate', 'Amount']]
    
    for item in sale.items.all():
        data.append([
            item.product.product_name[:15],
            str(item.quantity),
            f"{item.unit_price:.2f}",
            f"{item.line_total:.2f}"
        ])
    
    # Totals
    data.append(['', '', 'Subtotal:', f"{sale.subtotal:.2f}"])
    if sale.discount > 0:
        data.append(['', '', 'Discount:', f"-{sale.discount:.2f}"])
    if sale.tax > 0:
        data.append(['', '', 'VAT (13%):', f"{sale.tax:.2f}"])
    data.append(['', '', 'TOTAL:', f"{sale.total_amount:.2f}"])
    
    table = Table(data, colWidths=[1.3*inch, 0.5*inch, 0.6*inch, 0.6*inch])
    table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.1*inch))
    
    # Payment Method
    payment_info = f"Payment: {sale.get_payment_method_display()}"
    if sale.payment_status != 'paid':
        payment_info += f"\nDue: {sale.due_amount():.2f}"
    
    elements.append(Paragraph(payment_info, ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=8)))
    elements.append(Spacer(1, 0.1*inch))
    
    # Footer
    footer = "Thank You!\nVisit Again"
    elements.append(Paragraph(footer, ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=8)))
    
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_barcode_image(sku):
    """Generate barcode image for product SKU"""
    try:
        barcode_format = barcode.get_barcode_class('code128')
        barcode_obj = barcode_format(str(sku), writer=ImageWriter())
        
        buffer = BytesIO()
        barcode_obj.write(buffer)
        buffer.seek(0)
        return buffer
    except:
        return None

def calculate_sale_totals(items_data):
    """Calculate subtotal, discount, tax, and total"""
    subtotal = sum([item['unit_price'] * item['quantity'] for item in items_data])
    discount = subtotal * (items_data[0].get('discount_percent', 0) / 100) if items_data else 0
    amount_after_discount = subtotal - discount
    tax = amount_after_discount * (settings.VAT_PERCENT / 100)
    total = amount_after_discount + tax
    
    return {
        'subtotal': subtotal,
        'discount': discount,
        'tax': tax,
        'total': total
    }

def process_credit_sale(customer, amount):
    """Process credit sale and update customer balance"""
    from customers.models import Customer, CreditTransaction
    
    try:
        customer.current_credit += amount
        customer.save()
        
        CreditTransaction.objects.create(
            customer=customer,
            transaction_type='purchase',
            amount=amount,
            balance_after=customer.current_credit,
            description='Sale on credit'
        )
        return True
    except:
        return False

def process_payment(customer, amount):
    """Process payment against customer credit"""
    from customers.models import Customer, CreditTransaction
    
    try:
        customer.current_credit -= amount
        if customer.current_credit < 0:
            customer.current_credit = 0
        customer.save()
        
        CreditTransaction.objects.create(
            customer=customer,
            transaction_type='payment',
            amount=amount,
            balance_after=customer.current_credit,
            description='Payment received'
        )
        return True
    except:
        return False


# ========================================
# sales/views.py - POS & Billing Views

from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.db import transaction
from django.utils import timezone
from .models import Sale, SaleItem
from inventory.models import Product, Inventory
from customers.models import Customer
from .utils import generate_receipt_pdf
import json

def pos_view(request):
    """Main POS Interface"""
    context = {
        'categories': [],
    }
    return render(request, 'sales/pos.html', context)

@require_http_methods(["GET"])
def search_product_api(request):
    """API endpoint to search products by name or barcode"""
    query = request.GET.get('q', '')
    
    if len(query) < 2:
        return JsonResponse({'products': []})
    
    # Search by product name or barcode
    products = Product.objects.filter(
        models.Q(product_name__icontains=query) |
        models.Q(barcode__icontains=query) |
        models.Q(sku__icontains=query)
    )[:10]  # Limit to 10 results
    
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

@require_http_methods(["GET"])
def get_customer_api(request):
    """API endpoint to get customer by mobile number"""
    phone = request.GET.get('phone', '')
    
    try:
        customer = Customer.objects.get(
            models.Q(phone_number=phone) | models.Q(secondary_phone_number=phone)
        )
        return JsonResponse({
            'found': True,
            'name': customer.customer_name,
            'phone': customer.phone_number,
            'current_credit': str(customer.current_credit),
        })
    except Customer.DoesNotExist:
        return JsonResponse({'found': False})

@require_http_methods(["POST"])
@transaction.atomic
def create_sale_api(request):
    """API endpoint to create a sale"""
    try:
        data = json.loads(request.body)
        
        # Get or create customer
        customer = None
        if data.get('customer_phone'):
            customer, _ = Customer.objects.get_or_create(
                phone_number=data['customer_phone'],
                defaults={'customer_name': data.get('customer_name', 'Walk-in Customer')}
            )
        
        # Create sale
        sale = Sale.objects.create(
            customer=customer,
            cashier=request.user.profile,
            subtotal=float(data['subtotal']),
            discount=float(data.get('discount', 0)),
            discount_percent=float(data.get('discount_percent', 0)),
            tax=float(data['tax']),
            total_amount=float(data['total']),
            payment_method=data.get('payment_method', 'cash'),
            payment_status='paid' if float(data['paid_amount']) >= float(data['total']) else 'partial',
            paid_amount=float(data.get('paid_amount', 0)),
        )
        
        # Create sale items
        for item in data['items']:
            product = Product.objects.get(id=int(item['product_id']))
            SaleItem.objects.create(
                sale=sale,
                product=product,
                quantity=int(item['quantity']),
                unit_price=float(item['price']),
                discount_percent=float(item.get('discount', 0)),
                line_total=float(item['line_total']),
            )
            
            # Update inventory
            inventory = product.inventory
            inventory.quantity_in_stock -= int(item['quantity'])
            inventory.save()
        
        # Process credit sale if applicable
        if customer and data.get('payment_method') == 'credit':
            from customers.models import CreditTransaction
            customer.current_credit += float(data['total'])
            customer.save()
            CreditTransaction.objects.create(
                customer=customer,
                transaction_type='purchase',
                amount=float(data['total']),
                balance_after=customer.current_credit,
                related_sale=sale,
            )
        
        return JsonResponse({
            'success': True,
            'sale_number': sale.sale_number,
            'message': 'Sale created successfully'
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=400)

def print_receipt(request, sale_number):
    """Display receipt in printable format"""
    sale = get_object_or_404(Sale, sale_number=sale_number)
    context = {'sale': sale}
    return render(request, 'sales/receipt.html', context)

def receipt_pdf(request, sale_number):
    """Generate and download receipt as PDF"""
    sale = get_object_or_404(Sale, sale_number=sale_number)
    
    buffer = generate_receipt_pdf(sale)
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="receipt_{sale_number}.pdf"'
    
    return response

def sales_list(request):
    """View all sales transactions"""
    sales = Sale.objects.all().order_by('-sale_date')
    
    # Filter by date
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    
    if from_date:
        sales = sales.filter(sale_date__date__gte=from_date)
    if to_date:
        sales = sales.filter(sale_date__date__lte=to_date)
    
    context = {'sales': sales}
    return render(request, 'sales/sales_list.html', context)

def sales_detail(request, sale_number):
    """View detailed sale information"""
    sale = get_object_or_404(Sale, sale_number=sale_number)
    context = {'sale': sale}
    return render(request, 'sales/sales_detail.html', context)
