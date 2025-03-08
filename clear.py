from core.database import DatabaseManager

db_manager = DatabaseManager()
db_manager.cleanup_old_records(days=0)
