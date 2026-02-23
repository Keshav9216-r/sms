import logging

from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from .utils import get_current_tenant_db

logger = logging.getLogger('security')


class TenantModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        tenant_db = get_current_tenant_db()
        if not tenant_db:
            return None
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD) or kwargs.get('email')
        if not username or not password:
            return None
        try:
            user = UserModel.objects.using(tenant_db).get(**{UserModel.USERNAME_FIELD: username})
        except UserModel.DoesNotExist:
            return None
        if not user.check_password(password) or not self.user_can_authenticate(user):
            return None

        # Verify the user actually belongs to the current tenant
        from apps.accounts.models import UserProfile
        try:
            profile = UserProfile.objects.using(tenant_db).get(user=user)
            # Import here to avoid circular imports
            from .models import Tenant
            # Resolve current tenant from session/request to compare
            current_tenant_id = getattr(request, 'session', {}).get('tenant_id') if request else None
            if current_tenant_id and profile.tenant_id and profile.tenant_id != current_tenant_id:
                logger.warning(
                    "Tenant membership mismatch for user %s: profile tenant %s != session tenant %s",
                    username, profile.tenant_id, current_tenant_id,
                )
                return None
        except UserProfile.DoesNotExist:
            # No profile yet (e.g., freshly provisioned) — allow through
            pass

        return user

    def get_user(self, user_id):
        tenant_db = get_current_tenant_db()
        if not tenant_db:
            return None
        UserModel = get_user_model()
        try:
            return UserModel.objects.using(tenant_db).get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
