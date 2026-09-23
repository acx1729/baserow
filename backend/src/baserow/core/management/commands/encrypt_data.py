import sys

from django.core.management.base import BaseCommand

from baserow.core.encryption.handler import EncryptionHandler


class Command(BaseCommand):
    help = (
        "Encrypts the secrets that are still stored in plain text, and re-encrypts "
        "the secrets that are protected by an old key. Run it after upgrading "
        "Baserow, after changing BASEROW_ENCRYPTION_KEYS or BASEROW_ENCRYPTION_"
        "PROVIDER, and after rotating the HashiCorp Vault Transit key."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only report how many values must be encrypted.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=500,
            help="The number of rows that are processed at once.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        reports = EncryptionHandler().encrypt_existing_values(
            dry_run=dry_run, batch_size=options["batch_size"]
        )

        for report in reports:
            line = (
                f"{report.field}: {report.values} values, {report.to_encrypt} "
                f"{'to encrypt' if dry_run else 'encrypted'}"
            )
            if report.failed:
                line += f", {report.failed} could not be decrypted"
            self.stdout.write(line)

        to_encrypt = sum(report.to_encrypt for report in reports)
        failed = sum(report.failed for report in reports)
        if dry_run:
            self.stdout.write(f"{to_encrypt} values must be encrypted.")
        else:
            self.stdout.write(self.style.SUCCESS(f"Encrypted {to_encrypt} values."))

        if failed:
            self.stdout.write(
                self.style.ERROR(
                    f"{failed} values could not be decrypted. Make sure every key "
                    f"that was used to encrypt them is still configured."
                )
            )
            sys.exit(1)
