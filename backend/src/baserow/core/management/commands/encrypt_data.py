import sys
import time

from django.core.management.base import BaseCommand, CommandError

from baserow.core.encryption.exceptions import EncryptionError
from baserow.core.encryption.handler import (
    ENCRYPTION_ENABLED_RECHECK_SECONDS,
    EncryptionHandler,
    is_encryption_enabled,
)


class Command(BaseCommand):
    help = (
        "Enables encryption at rest and encrypts the secrets that are still stored in "
        "plain text, and re-encrypts the secrets that are protected by an old key. "
        "Run it once every instance runs the upgraded version, and after changing "
        "BASEROW_ENCRYPTION_KEYS or BASEROW_ENCRYPTION_PROVIDER, or rotating the "
        "HashiCorp Vault Transit key."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Only report how many values must be encrypted.",
        )
        parser.add_argument(
            "--if-not-enabled",
            action="store_true",
            help="Only run when encryption at rest isn't enabled yet.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=100,
            help="The number of rows that are read at once.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        batch_size = options["batch_size"]
        handler = EncryptionHandler()

        if options["if_not_enabled"] and is_encryption_enabled():
            self.stdout.write("Encryption at rest is already enabled.")
            return

        try:
            handler.check_key_provider()
        except EncryptionError as exc:
            raise CommandError(
                f"The key provider can't be used, nothing has been changed: {exc}"
            ) from exc

        try:
            reports = self.encrypt(handler, dry_run, batch_size)
        except EncryptionError as exc:
            raise CommandError(
                f"{exc} Run this command again once the problem is solved."
            ) from exc

        self.write_reports(reports, dry_run)

    def encrypt(self, handler, dry_run, batch_size):
        if dry_run:
            if not is_encryption_enabled():
                self.stdout.write(
                    "Encryption at rest isn't enabled yet: secrets are written in "
                    "plain text until this command runs without --dry-run."
                )
            reports = handler.encrypt_existing_values(
                dry_run=True, batch_size=batch_size
            )
        else:
            was_disabled = not is_encryption_enabled()
            reports = handler.encrypt_existing_values(batch_size=batch_size)
            if was_disabled:
                self.stdout.write("Encryption at rest is enabled.")
                # Other processes can keep writing values in plain text until they
                # read the setting again, those are encrypted by a second pass.
                time.sleep(ENCRYPTION_ENABLED_RECHECK_SECONDS)
                for report, extra in zip(
                    reports,
                    handler.encrypt_existing_values(batch_size=batch_size),
                ):
                    report.encrypted += extra.encrypted
                    report.failed = extra.failed
        return reports

    def write_reports(self, reports, dry_run):
        for report in reports:
            line = (
                f"{report.field}: {report.values} values, "
                f"{report.to_encrypt if dry_run else report.encrypted} "
                f"{'to encrypt' if dry_run else 'encrypted'}"
            )
            if report.failed:
                line += f", {report.failed} could not be decrypted"
            self.stdout.write(line)

        failed = sum(report.failed for report in reports)
        if dry_run:
            to_encrypt = sum(report.to_encrypt for report in reports)
            self.stdout.write(f"{to_encrypt} values must be encrypted.")
        else:
            encrypted = sum(report.encrypted for report in reports)
            self.stdout.write(self.style.SUCCESS(f"Encrypted {encrypted} values."))

        if failed:
            self.stdout.write(
                self.style.ERROR(
                    f"{failed} values could not be decrypted. Make sure every key "
                    f"that was used to encrypt them is still configured."
                )
            )
            sys.exit(1)
