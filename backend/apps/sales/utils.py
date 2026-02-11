# sales/utils.py - PDF Receipt & Utility Functions

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from io import BytesIO
from django.conf import settings
import barcode
from barcode.writer import ImageWriter


def number_to_words(amount):
    units = [
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
        "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
        "eighteen", "nineteen"
    ]
    tens = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]

    def two_digit(n):
        if n < 20:
            return units[n]
        return tens[n // 10] + ("-" + units[n % 10] if n % 10 else "")

    def three_digit(n):
        if n < 100:
            return two_digit(n)
        rem = n % 100
        return units[n // 100] + " hundred" + (" " + two_digit(rem) if rem else "")

    def chunk_to_words(n):
        parts = []
        billions = n // 1_000_000_000
        millions = (n // 1_000_000) % 1_000
        thousands = (n // 1_000) % 1_000
        remainder = n % 1_000
        if billions:
            parts.append(three_digit(billions) + " billion")
        if millions:
            parts.append(three_digit(millions) + " million")
        if thousands:
            parts.append(three_digit(thousands) + " thousand")
        if remainder:
            parts.append(three_digit(remainder))
        return " ".join(parts) if parts else "zero"

    amount = round(float(amount), 2)
    rupees = int(amount)
    paise = int(round((amount - rupees) * 100))
    words = f"{chunk_to_words(rupees)} rupees"
    if paise:
        words += f" and {two_digit(paise)} paise"
    return words

def generate_receipt_pdf(sale):
    """Generate PDF receipt for a sale"""
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        rightMargin=0.6 * inch,
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # Shop Header
    shop_name = Paragraph('<b>Kopila Books &amp; stationery</b>', ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=16))
    shop_address = Paragraph('Gaindakot, Nepal', ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=12))
    shop_phone = Paragraph('Ph: 9845817460', ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=12))
    
    elements.append(shop_name)
    elements.append(Spacer(1, 0.05*inch))
    elements.append(shop_address)
    elements.append(shop_phone)
    elements.append(Spacer(1, 0.1*inch))
    
    # Sale Info
    receipt_no = sale.receipt_number or sale.sale_number
    sale_info_lines = [
        f"<b>Receipt No:</b> {receipt_no}",
        f"<b>Purchased Date:</b> {sale.sale_date.strftime('%Y-%m-%d %H:%M')}",
    ]
    if sale.irregular_customer:
        customer_name = f"IR: {sale.irregular_customer.customer_name}"
        customer_address = sale.irregular_customer.address or ''
        sale_info_lines.append(f"<b>Customer:</b> {customer_name}")
        sale_info_lines.append(f"<b>Address:</b> {customer_address}" if customer_address else "<b>Address:</b> —")
    elif sale.customer:
        customer_name = sale.customer.customer_name
        customer_address = sale.customer.address or ''
        sale_info_lines.append(f"<b>Customer:</b> {customer_name}")
        sale_info_lines.append(f"<b>Address:</b> {customer_address}" if customer_address else "<b>Address:</b> —")

    sale_info = "<br/>".join(sale_info_lines)

    elements.append(Paragraph(sale_info, ParagraphStyle(name='left', alignment=TA_LEFT, fontSize=10)))
    elements.append(Spacer(1, 0.2*inch))
    
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
    
    table = Table(data, colWidths=[2.8*inch, 0.8*inch, 1.0*inch, 1.0*inch])
    table.setStyle(TableStyle([
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('ALIGN', (0, 0), (-1, -1), 'RIGHT'),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
    ]))
    
    elements.append(table)
    elements.append(Spacer(1, 0.15*inch))

    amount_words = number_to_words(sale.total_amount)
    salesperson = ""
    if getattr(sale, 'cashier', None) and getattr(sale.cashier, 'user', None):
        salesperson = sale.cashier.user.get_full_name() or sale.cashier.user.username
    credit_balance = ""
    if getattr(sale, 'customer', None):
        credit_balance = f"Customer Credit Balance: {sale.customer.current_credit}"
    amount_block = (
        f"<b>Amount in Words:</b> {amount_words}" +
        (f"<br/><b>Sales Person:</b> {salesperson}" if salesperson else "") +
        (f"<br/><b>{credit_balance}</b>" if credit_balance else "")
    )
    elements.append(Paragraph(amount_block, ParagraphStyle(name='left', alignment=TA_LEFT, fontSize=10)))
    elements.append(Spacer(1, 0.1*inch))
    
    # Payment Method
    payment_lines = [
        f"<b>Payment:</b> {sale.get_payment_method_display()}",
    ]
    payment_info = "<br/>".join(payment_lines)

    elements.append(Paragraph(payment_info, ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=10)))
    elements.append(Spacer(1, 0.1*inch))
    
    # Footer
    footer = "<b><i>Thank You!</i></b><br/><b><i>Visit Again</i></b> ❤️"
    elements.append(Paragraph(footer, ParagraphStyle(name='center', alignment=TA_CENTER, fontSize=10)))
    
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
    from apps.customers.models import Customer, CreditTransaction
    
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
    from apps.customers.models import Customer, CreditTransaction
    
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
