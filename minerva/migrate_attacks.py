import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor

SQLITE_DB = "/app/instance/aegis_dev.db"

PG_HOST = "db"
PG_PORT = 5432
PG_DB = "aegis"
PG_USER = "aegis"
PG_PASSWORD = "aegis_secret_password"


def b(v, default=False):
    if v is None:
        return default
    return bool(v)


def connect_sqlite():
    conn = sqlite3.connect(SQLITE_DB)
    conn.row_factory = sqlite3.Row
    return conn


def connect_pg():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD,
    )


def migrate_main_categories(sqlite_cur, pg_cur, pg_conn):
    sqlite_cur.execute("SELECT * FROM main_categories")
    rows = sqlite_cur.fetchall()
    inserted = skipped = errors = 0

    for row in rows:
        row = dict(row)

        try:
            pg_cur.execute("SELECT id FROM main_categories WHERE id = %s", (row["id"],))
            if pg_cur.fetchone():
                skipped += 1
                continue

            pg_cur.execute("SELECT id FROM main_categories WHERE name = %s", (row["name"],))
            if pg_cur.fetchone():
                skipped += 1
                print(f"Skipped existing main category by name: {row['name']}")
                continue

            pg_cur.execute(
                """
                INSERT INTO main_categories (
                    id, name, description, icon, color,
                    is_active, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row.get("id"),
                    row.get("name"),
                    row.get("description"),
                    row.get("icon"),
                    row.get("color"),
                    b(row.get("is_active"), True),
                    row.get("created_at"),
                    row.get("updated_at"),
                ),
            )
            pg_conn.commit()
            inserted += 1

        except Exception as e:
            pg_conn.rollback()
            errors += 1
            print(f"Main category insert error: {row.get('name')} -> {e}")

    print(f"main_categories -> inserted={inserted}, skipped={skipped}, errors={errors}")


def migrate_sub_categories(sqlite_cur, pg_cur, pg_conn):
    sqlite_cur.execute("SELECT * FROM sub_categories")
    rows = sqlite_cur.fetchall()
    inserted = skipped = errors = 0

    for row in rows:
        row = dict(row)

        try:
            pg_cur.execute("SELECT id FROM sub_categories WHERE id = %s", (row["id"],))
            if pg_cur.fetchone():
                skipped += 1
                continue

            pg_cur.execute("SELECT id FROM sub_categories WHERE name = %s", (row["name"],))
            if pg_cur.fetchone():
                skipped += 1
                print(f"Skipped existing sub category by name: {row['name']}")
                continue

            # Find matching Postgres main category by name
            sqlite_cur.execute(
                "SELECT name FROM main_categories WHERE id = ?",
                (row.get("main_category_id"),)
            )
            sqlite_main = sqlite_cur.fetchone()

            if not sqlite_main:
                raise Exception(f"SQLite main category not found for id {row.get('main_category_id')}")

            sqlite_main_name = sqlite_main["name"]

            pg_cur.execute(
                "SELECT id FROM main_categories WHERE name = %s",
                (sqlite_main_name,)
            )
            pg_main = pg_cur.fetchone()

            if not pg_main:
                raise Exception(f"Postgres main category not found for name {sqlite_main_name}")

            postgres_main_category_id = pg_main["id"]

            pg_cur.execute(
                """
                INSERT INTO sub_categories (
                    id, name, description, icon, color,
                    is_active, "order", main_category_id, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    row.get("id"),
                    row.get("name"),
                    row.get("description"),
                    row.get("icon"),
                    row.get("color"),
                    b(row.get("is_active"), True),
                    row.get("sort_order"),
                    postgres_main_category_id,
                    row.get("created_at"),
                    row.get("updated_at"),
                ),
            )
            pg_conn.commit()
            inserted += 1

        except Exception as e:
            pg_conn.rollback()
            errors += 1
            print(f"Sub category insert error: {row.get('name')} -> {e}")

    print(f"sub_categories -> inserted={inserted}, skipped={skipped}, errors={errors}")


def migrate_attacks(sqlite_cur, pg_cur, pg_conn):
    sqlite_cur.execute("SELECT * FROM attacks")
    rows = sqlite_cur.fetchall()
    inserted = skipped = errors = 0

    for row in rows:
        row = dict(row)

        try:
            pg_cur.execute("SELECT id FROM attacks WHERE id = %s", (row["id"],))
            if pg_cur.fetchone():
                skipped += 1
                continue

            # Get SQLite subcategory name from SQLite subcategory_id
            sqlite_cur.execute(
                "SELECT name FROM sub_categories WHERE id = ?",
                (row.get("subcategory_id"),)
            )
            sqlite_sub = sqlite_cur.fetchone()

            if not sqlite_sub:
                raise Exception(f"SQLite subcategory not found for id {row.get('subcategory_id')}")

            sqlite_sub_name = sqlite_sub["name"]

            # Find matching Postgres subcategory by name
            pg_cur.execute(
                "SELECT id FROM sub_categories WHERE name = %s",
                (sqlite_sub_name,)
            )
            pg_sub = pg_cur.fetchone()

            if not pg_sub:
                raise Exception(f"Postgres subcategory not found for name {sqlite_sub_name}")

            postgres_subcategory_id = pg_sub["id"]

            pg_cur.execute(
                """
                INSERT INTO attacks (
                    id, name, description, severity, attack_type, mitre_id,
                    cve_ids, script_path, script_content, script_language,
                    config_schema, default_config, requires_authentication,
                    timeout, parallel_safe, author, version, tags,
                    "references", is_active, is_verified, subcategory_id,
                    created_at, updated_at
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s, %s
                )
                """,
                (
                    row.get("id"),
                    row.get("name"),
                    row.get("description"),
                    row.get("severity"),
                    row.get("attack_type"),
                    row.get("mitre_id"),
                    row.get("cve_ids"),
                    row.get("script_path"),
                    row.get("script_content"),
                    row.get("script_language"),
                    row.get("config_schema"),
                    row.get("default_config"),
                    b(row.get("requires_authentication"), False),
                    row.get("timeout"),
                    b(row.get("parallel_safe"), False),
                    row.get("author"),
                    row.get("version"),
                    row.get("tags"),
                    row.get("references"),
                    b(row.get("is_active"), True),
                    b(row.get("is_verified"), False),
                    postgres_subcategory_id,
                    row.get("created_at"),
                    row.get("updated_at"),
                ),
            )
            pg_conn.commit()
            inserted += 1

        except Exception as e:
            pg_conn.rollback()
            errors += 1
            print(f"Attack insert error: {row.get('name')} -> {e}")

    print(f"attacks -> inserted={inserted}, skipped={skipped}, errors={errors}")


def main():
    sqlite_conn = connect_sqlite()
    sqlite_cur = sqlite_conn.cursor()

    pg_conn = connect_pg()
    pg_cur = pg_conn.cursor(cursor_factory=RealDictCursor)

    migrate_main_categories(sqlite_cur, pg_cur, pg_conn)
    migrate_sub_categories(sqlite_cur, pg_cur, pg_conn)
    migrate_attacks(sqlite_cur, pg_cur, pg_conn)

    sqlite_cur.close()
    sqlite_conn.close()
    pg_cur.close()
    pg_conn.close()


if __name__ == "__main__":
    main()