import unittest

from sqlalchemy import create_engine

from app.db import _migrate_ticket_status_nullable


class TicketMigrationTest(unittest.TestCase):
    def test_legacy_status_becomes_nullable_and_untriaged(self):
        engine = create_engine("sqlite://")
        with engine.begin() as connection:
            connection.exec_driver_sql("""
                CREATE TABLE tickets (
                    id VARCHAR NOT NULL PRIMARY KEY, title VARCHAR NOT NULL,
                    threat_type VARCHAR NOT NULL, severity VARCHAR NOT NULL,
                    status VARCHAR NOT NULL, source_ip VARCHAR, target_host VARCHAR,
                    description TEXT NOT NULL, created_at DATETIME NOT NULL
                )
            """)
            connection.exec_driver_sql("""
                INSERT INTO tickets VALUES
                ('TKT-1', 'Test', 'phishing', 'HIGH', 'resolved', NULL, NULL, 'Test', '2026-01-01')
            """)

        _migrate_ticket_status_nullable(engine)

        with engine.connect() as connection:
            columns = connection.exec_driver_sql("PRAGMA table_info(tickets)").mappings().all()
            status = next(column for column in columns if column["name"] == "status")
            value = connection.exec_driver_sql("SELECT status FROM tickets").scalar_one()
        self.assertEqual(status["notnull"], 0)
        self.assertIsNone(value)


if __name__ == "__main__":
    unittest.main()
