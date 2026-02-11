from __future__ import annotations

from datetime import datetime
from pathlib import Path

from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.conf import settings


class Command(BaseCommand):
    help = "Backup database and app data into a date-based folder."

    def handle(self, *args, **options):
        base_dir = Path(settings.BASE_DIR)
        backups_dir = base_dir / "backups" / datetime.now().strftime("%Y-%m-%d")
        backups_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%H%M%S")
        db_path = base_dir / "db.sqlite3"
        db_backup = backups_dir / f"db_{timestamp}.sqlite3"
        data_backup = backups_dir / f"data_{timestamp}.json"

        if db_path.exists():
            db_backup.write_bytes(db_path.read_bytes())

        with data_backup.open("w", encoding="utf-8") as output:
            call_command("dumpdata", "inventory", "customers", "sales", stdout=output)

        self.stdout.write(self.style.SUCCESS(f"Backup saved in {backups_dir}"))
