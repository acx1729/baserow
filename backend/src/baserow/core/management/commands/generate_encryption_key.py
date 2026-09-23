from django.core.management.base import BaseCommand

from baserow.core.encryption.key_provider_types import generate_encryption_key


class Command(BaseCommand):
    help = (
        "Generates a random key that can be used in BASEROW_ENCRYPTION_KEYS to "
        "encrypt secrets at rest with the local key provider."
    )

    def handle(self, *args, **options):
        self.stdout.write(generate_encryption_key())
