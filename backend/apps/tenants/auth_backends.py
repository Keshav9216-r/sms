from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model
from .utils import get_current_tenant_db


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
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def get_user(self, user_id):
        tenant_db = get_current_tenant_db()
        if not tenant_db:
            return None
        UserModel = get_user_model()
        try:
            return UserModel.objects.using(tenant_db).get(pk=user_id)
        except UserModel.DoesNotExist:
            return None
