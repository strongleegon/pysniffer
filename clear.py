from core.database import DatabaseManager
db=DatabaseManager()
db.cleanup_old_records(days=0)