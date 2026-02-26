from datetime import timedelta
import logging

from django.db.models import F
from django.utils import timezone


logger = logging.getLogger(__name__)


def notifications(request):
    """Inject notification data (low stock, large dues, overdue payments) into every template."""
    if not request.user.is_authenticated:
        return {}

    tenant_db = getattr(request, 'tenant_db', None)
    if not tenant_db:
        return {}

    # Skip for superadmin users — they don't manage shop stock/dues
    try:
        from apps.accounts.models import UserProfile
        profile = UserProfile.objects.using(tenant_db).filter(user_id=request.user.id).first()
        if profile and profile.role == 'superadmin':
            return {}
    except Exception:
        return {}

    items = []

    # ── 1. Low stock items ────────────────────────────────────────────────────
    try:
        from apps.inventory.models import Inventory
        low_stock = (
            Inventory.objects.using(tenant_db)
            .filter(quantity_in_stock__lte=F('product__reorder_level'))
            .select_related('product')
            .order_by('quantity_in_stock')[:10]
        )
        for inv in low_stock:
            items.append({
                'category': 'low_stock',
                'label': 'Low Stock',
                'color': '#f59e0b',
                'bg': '#fffbeb',
                'text': f'{inv.product.product_name} — {inv.quantity_in_stock} left (min {inv.product.reorder_level})',
                'url': '/inventory/',
            })
    except Exception:
        logger.exception("Failed to build low-stock notifications")

    # ── 2. Customers with due amount > 10 000 ────────────────────────────────
    try:
        from apps.customers.models import Customer
        big_dues = (
            Customer.objects.using(tenant_db)
            .filter(current_credit__gt=10000)
            .order_by('-current_credit')[:10]
        )
        for cust in big_dues:
            items.append({
                'category': 'large_due',
                'label': 'Large Due',
                'color': '#ef4444',
                'bg': '#fef2f2',
                'text': f'{cust.customer_name} owes Rs.\u00a0{cust.current_credit:,.0f}',
                'url': '/customers/',
            })
    except Exception:
        logger.exception("Failed to build large-due notifications")

    # ── 3. Overdue payments (pending/partial older than 30 days) ─────────────
    try:
        from apps.sales.models import Sale
        cutoff = timezone.now() - timedelta(days=30)
        overdue = (
            Sale.objects.using(tenant_db)
            .filter(payment_status__in=['partial', 'pending'], sale_date__lt=cutoff)
            .select_related('customer')
            .order_by('sale_date')[:10]
        )
        for sale in overdue:
            due = sale.total_amount - sale.paid_amount
            cname = sale.customer.customer_name if sale.customer else 'Walk-in'
            days = (timezone.now() - sale.sale_date).days
            items.append({
                'category': 'overdue',
                'label': 'Overdue',
                'color': '#dc2626',
                'bg': '#fef2f2',
                'text': f'{cname} — Rs.\u00a0{due:,.0f} due ({days}\u00a0days old)',
                'url': '/sales/',
            })
    except Exception:
        logger.exception("Failed to build overdue notifications")

    return {
        'notifications': items,
        'notification_count': len(items),
    }
