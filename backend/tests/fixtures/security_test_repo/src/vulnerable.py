"""
SECURITY TEST FIXTURE — Python
Intentionally vulnerable examples for DevPilot Phase 6 testing.
These are SYNTHETIC vulnerabilities. Do not use this in production.
All secrets here are FAKE test credentials only.
"""

import subprocess
import os

# FAKE test credentials — clearly synthetic, not real
# TEST_SECRET_DO_NOT_USE — these are fake values for scanner testing only
API_KEY = "TEST_SECRET_DO_NOT_USE_123456"
DATABASE_PASSWORD = "fake_test_password_abcdefgh"


# SQL injection — user input directly concatenated
def get_user(db, user_id):
    # This is intentionally unsafe for testing
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)


# Command injection — user input in subprocess
def run_command(user_input):
    # This is intentionally unsafe for testing
    result = subprocess.run(["ls", user_input], capture_output=True)
    return result


# Hardcoded secret in function (different pattern)
def connect_db():
    # FAKE: synthetic test value
    connection_string = "postgres://admin:FAKE_TEST_PASS_9999@localhost:5432/mydb"
    return connection_string


# Broad exception handling
def risky_operation():
    try:
        result = eval("1 + 1")  # eval without user input
        return result
    except Exception:
        pass


# TODO marker
def unfinished_work():
    # TODO: implement proper validation
    pass
