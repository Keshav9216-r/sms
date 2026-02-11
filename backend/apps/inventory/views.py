from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import Q
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import HttpResponse, JsonResponse
from .models import Product, Category, Inventory
import barcode
from barcode.writer import ImageWriter
import io


def _generate_unique_barcode(base_barcode, exclude_id=None):
    if not base_barcode:
        return None
    base_barcode = base_barcode.strip()
    if not base_barcode:
        return None
    queryset = Product.objects.all()
    if exclude_id:
        queryset = queryset.exclude(id=exclude_id)
    if not queryset.filter(barcode=base_barcode).exists():
        return base_barcode
    counter = 1
    while True:
        candidate = f"{base_barcode}({counter})"
        if not queryset.filter(barcode=candidate).exists():
            return candidate
        counter += 1

@login_required
def product_list(request, category_type=None):
    products = Product.objects.select_related('category', 'inventory').all()
    query = request.GET.get('q', '').strip()
    filter_by = request.GET.get('filter_by', 'name')
    sort_by = request.GET.get('sort_by', 'name_asc')
    category_type = category_type or request.GET.get('category_type', '').strip()

    if category_type in {'books', 'stationery'}:
        products = products.filter(category__category_type=category_type)

    if query:
        if filter_by == 'sku':
            products = products.filter(sku__icontains=query)
        elif filter_by == 'barcode':
            products = products.filter(barcode__icontains=query)
        elif filter_by == 'category':
            products = products.filter(category__name__icontains=query)
        elif filter_by == 'price':
            try:
                price_value = float(query)
                products = products.filter(selling_price=price_value)
            except ValueError:
                products = products.none()
        elif filter_by == 'all':
            products = products.filter(
                Q(product_name__icontains=query) |
                Q(sku__icontains=query) |
                Q(barcode__icontains=query) |
                Q(category__name__icontains=query)
            )
        else:
            products = products.filter(product_name__icontains=query)

    if sort_by == 'name_desc':
        products = products.order_by('-product_name')
    elif sort_by == 'price_asc':
        products = products.order_by('selling_price', 'product_name')
    elif sort_by == 'price_desc':
        products = products.order_by('-selling_price', 'product_name')
    elif sort_by == 'stock_asc':
        products = products.order_by('inventory__quantity_in_stock', 'product_name')
    elif sort_by == 'stock_desc':
        products = products.order_by('-inventory__quantity_in_stock', 'product_name')
    else:
        products = products.order_by('product_name')
    
    context = {
        'products': products,
        'categories': Category.objects.all(),
        'query': query,
        'filter_by': filter_by,
        'sort_by': sort_by,
        'category_type': category_type,
    }
    return render(request, 'inventory/products_list.html', context)


@login_required
def product_list_books(request):
    return product_list(request, category_type='books')


@login_required
def product_list_stationery(request):
    return product_list(request, category_type='stationery')

@login_required
def product_detail(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    inventory = Inventory.objects.get(product=product)
    context = {
        'product': product,
        'inventory': inventory
    }
    return render(request, 'inventory/product_detail.html', context)

@login_required
def product_add(request):
    if request.method == 'POST':
        sku = request.POST.get('sku')
        product_name = request.POST.get('product_name')
        category_id = request.POST.get('category')
        cost_price = request.POST.get('cost_price')
        selling_price = request.POST.get('selling_price')
        description = request.POST.get('description') or ''
        supplier = request.POST.get('supplier') or ''
        book_name = request.POST.get('book_name') or ''
        book_class = request.POST.get('book_class') or ''
        book_publication = request.POST.get('book_publication') or ''
        barcode_value = (request.POST.get('barcode') or '').strip() or None
        wholesale_price = request.POST.get('wholesale_price') or None
        unit = request.POST.get('unit') or 'piece'
        reorder_level = request.POST.get('reorder_level') or 10
        initial_quantity = int(request.POST.get('quantity_in_stock') or 0)
        image = request.FILES.get('image')
        if not category_id:
            messages.error(request, 'Please select a category.')
            return render(request, 'inventory/product_add.html', {'categories': Category.objects.all()})
        try:
            category = Category.objects.get(id=category_id)
        except (Category.DoesNotExist, ValueError):
            category = Category.objects.filter(name__iexact=str(category_id).strip()).first()
            if not category:
                messages.error(request, 'Selected category is invalid.')
                return render(request, 'inventory/product_add.html', {'categories': Category.objects.all()})
        try:
            product = Product.objects.create(
                sku=sku,
                product_name=product_name,
                category=category,
                description=description,
                supplier=supplier,
                book_name=book_name,
                book_class=book_class,
                book_publication=book_publication,
                cost_price=cost_price,
                selling_price=selling_price,
                barcode=_generate_unique_barcode(barcode_value or sku),
                wholesale_price=wholesale_price,
                unit=unit,
                reorder_level=reorder_level,
                image=image,
            )
        except Exception as exc:
            messages.error(request, f"Unable to save product: {exc}")
            return redirect('product_add')
        
        Inventory.objects.create(product=product, quantity_in_stock=initial_quantity)
        return redirect('product_list')
    
    context = {'categories': Category.objects.all()}
    return render(request, 'inventory/product_add.html', context)

@login_required
def product_edit(request, pk):
    product = get_object_or_404(Product, id=pk)
    if request.method == 'POST':
        new_sku = (request.POST.get('sku') or '').strip()
        if not new_sku:
            messages.error(request, 'SKU is required.')
            context = {
                'product': product,
                'categories': Category.objects.all()
            }
            return render(request, 'inventory/product_edit.html', context)
        if Product.objects.exclude(id=product.id).filter(sku=new_sku).exists():
            messages.error(request, 'SKU already exists. Please use a different SKU.')
            context = {
                'product': product,
                'categories': Category.objects.all()
            }
            return render(request, 'inventory/product_edit.html', context)
        product.sku = new_sku
        product.product_name = request.POST.get('product_name')
        product.category_id = request.POST.get('category')
        product.description = request.POST.get('description') or ''
        product.supplier = request.POST.get('supplier') or ''
        product.book_name = request.POST.get('book_name') or ''
        product.book_class = request.POST.get('book_class') or ''
        product.book_publication = request.POST.get('book_publication') or ''
        product.cost_price = request.POST.get('cost_price')
        product.selling_price = request.POST.get('selling_price')
        new_barcode = (request.POST.get('barcode') or '').strip() or None
        if not new_barcode:
            new_barcode = product.barcode or product.sku
        if new_barcode == product.barcode:
            product.barcode = new_barcode
        else:
            product.barcode = _generate_unique_barcode(new_barcode, exclude_id=product.id)
        product.wholesale_price = request.POST.get('wholesale_price') or None
        product.unit = request.POST.get('unit') or product.unit
        product.reorder_level = request.POST.get('reorder_level') or product.reorder_level
        image = request.FILES.get('image')
        if image:
            product.image = image
        try:
            product.save()
            return redirect('product_list')
        except Exception as exc:
            messages.error(request, f"Unable to save product: {exc}")
    
    context = {
        'product': product,
        'categories': Category.objects.all()
    }
    return render(request, 'inventory/product_edit.html', context)

@login_required
def product_delete(request, pk):
    product = get_object_or_404(Product, id=pk)
    if request.method == 'POST':
        product.delete()
        messages.success(request, 'Product deleted successfully.')
        return redirect('product_list')
    
    context = {'product': product}
    return render(request, 'inventory/product_delete.html', context)

@login_required
def category_list(request):
    categories = Category.objects.all()
    context = {'categories': categories}
    return render(request, 'inventory/category_list.html', context)

@login_required
def category_add(request):
    if request.method == 'POST':
        name = (request.POST.get('name') or '').strip()
        category_type = (request.POST.get('category_type') or '').strip()
        description = (request.POST.get('description') or '').strip()

        if not name or not category_type:
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Name and type are required.'}, status=400)
            messages.error(request, 'Name and type are required.')
            return render(request, 'inventory/category_add.html')

        if Category.objects.filter(name__iexact=name).exists():
            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Category name already exists.'}, status=400)
            messages.error(request, 'Category name already exists.')
            return render(request, 'inventory/category_add.html')

        category = Category.objects.create(
            name=name,
            category_type=category_type,
            description=description,
        )

        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({
                'id': category.id,
                'name': category.name,
                'category_type': category.category_type,
            })
        return redirect('category_list')
    
    return render(request, 'inventory/category_add.html')

@login_required
def category_edit(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    if request.method == 'POST':
        category.name = request.POST.get('name')
        category.category_type = request.POST.get('category_type')
        category.save()
        return redirect('category_list')
    
    context = {'category': category}
    return render(request, 'inventory/category_edit.html', context)

@login_required
def category_delete(request, category_id):
    category = get_object_or_404(Category, id=category_id)
    if request.method == 'POST':
        category.delete()
        messages.success(request, 'Category deleted successfully.')
        return redirect('category_list')
    
    context = {'category': category}
    return render(request, 'inventory/category_delete.html', context)

@login_required
def generate_barcode(request, product_id):
    product = get_object_or_404(Product, id=product_id)
    barcode_format = barcode.get_barcode_class('code128')
    barcode_obj = barcode_format(str(product.sku), writer=ImageWriter())
    
    buffer = io.BytesIO()
    barcode_obj.write(buffer)
    buffer.seek(0)
    
    return HttpResponse(buffer.getvalue(), content_type='image/png')

@login_required
def low_stock_report(request):
    low_stock_items = Inventory.objects.filter(quantity_in_stock__lt=10)
    context = {'items': low_stock_items}
    return render(request, 'inventory/low_stock.html', context)

@login_required
def inventory_list(request):
    inventory_items = Inventory.objects.select_related('product').all()
    context = {'inventory_items': inventory_items}
    return render(request, 'inventory/inventory_list.html', context)

@login_required
def inventory_detail(request, pk):
    inventory = get_object_or_404(Inventory, pk=pk)
    context = {'inventory': inventory}
    return render(request, 'inventory/inventory_detail.html', context)

@login_required
def stock_adjust(request, pk):
    inventory = get_object_or_404(Inventory, pk=pk)
    if request.method == 'POST':
        adjustment = int(request.POST.get('adjustment', 0))
        inventory.quantity_in_stock += adjustment
        inventory.save()
        return redirect('inventory_detail', pk=pk)
    context = {'inventory': inventory}
    return render(request, 'inventory/stock_adjust.html', context)
