from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from apps.accounts.models import UserProfile


class Command(BaseCommand):
    help = 'Create a superadmin user'

    def add_arguments(self, parser):
        parser.add_argument('--email', type=str, help='Superadmin email')
        parser.add_argument('--password', type=str, help='Superadmin password')

    def handle(self, *args, **options):
        email = options.get('email') or input('Enter superadmin email: ')
        password = options.get('password') or input('Enter superadmin password: ')

        if User.objects.filter(email__iexact=email).exists():
            self.stdout.write(self.style.ERROR('Email already exists'))
            return

        superadmin = User.objects.create_superuser(
            username=email,
            email=email,
            password=password
        )
        
        UserProfile.objects.create(user=superadmin, role='superadmin')
        
        self.stdout.write(
            self.style.SUCCESS(f'Superadmin "{email}" created successfully')
        )
