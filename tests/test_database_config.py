from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from sqlalchemy import URL

from cti.db.session import database_url


class DatabaseConfigurationTests(unittest.TestCase):
    def test_supabase_components_build_encoded_tls_url(self) -> None:
        settings = {
            "SITE_DATABASE_URL": "",
            "SUPABASE_DB_HOST": "aws-0-example.pooler.supabase.com",
            "SUPABASE_DB_PORT": "5432",
            "SUPABASE_DB_NAME": "postgres",
            "SUPABASE_DB_USER": "postgres.projectref",
            "SUPABASE_DB_PASSWORD": "special@password/with#symbols",
        }
        with patch.dict(os.environ, settings, clear=False):
            url = database_url()

        self.assertIsInstance(url, URL)
        self.assertEqual(url.drivername, "postgresql+psycopg")
        self.assertEqual(url.host, settings["SUPABASE_DB_HOST"])
        self.assertEqual(url.port, 5432)
        self.assertEqual(url.password, settings["SUPABASE_DB_PASSWORD"])
        self.assertEqual(url.query["sslmode"], "require")


if __name__ == "__main__":
    unittest.main()
