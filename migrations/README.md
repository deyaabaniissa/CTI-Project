# Database migrations

Set `DATABASE_URL` in `.env`, then run:

```powershell
.\.venv\Scripts\alembic.exe upgrade head
```

The project expects a PostgreSQL connection string such as:

```text
postgresql+psycopg://cti_app:replace-me@127.0.0.1:5432/healthcare_cti
```

API keys remain in `.env`; no provider secret is stored in a database table.
