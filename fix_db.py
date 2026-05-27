import sys
import os

sys.path.append(os.path.abspath("sankofaeye_web"))

from app import app, db
from sqlalchemy import text

print(f"[*] Targeting active relative database file...")

with app.app_context():
    # 1. Force SQLAlchemy to create any tables (like users) if they are missing
    print("[*] Running db.create_all() to build missing tables...")
    db.create_all()
    print("[+] Core database initialization complete.")

    # 2. Add the payment metadata columns safely
    with db.engine.begin() as connection:
        print("[*] Checking / injecting stripe_customer_id...")
        try:
            connection.execute(text("ALTER TABLE users ADD COLUMN stripe_customer_id TEXT;"))
            print("[+] Column stripe_customer_id added successfully.")
        except Exception as e:
            if "duplicate column name" in str(e).lower():
                print("[~] stripe_customer_id already exists. Skipping.")
            else:
                print(f"[!] Info: {e}")

        print("[*] Checking / injecting stripe_subscription_id...")
        try:
            connection.execute(text("ALTER TABLE users ADD COLUMN stripe_subscription_id TEXT;"))
            print("[+] Column stripe_subscription_id added successfully.")
        except Exception as e:
            if "duplicate column name" in str(e).lower():
                print("[~] stripe_subscription_id already exists. Skipping.")
            else:
                print(f"[!] Info: {e}")

print("[+] Database sync completed successfully.")
