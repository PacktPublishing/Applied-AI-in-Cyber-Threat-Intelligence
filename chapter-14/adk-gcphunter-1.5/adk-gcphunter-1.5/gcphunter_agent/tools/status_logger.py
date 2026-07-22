"""Simple status logging for hunt progress tracking"""
from datetime import datetime
from pathlib import Path

def log_status(message: str, log_file: str = "hunt_status.log", max_size_mb: int = 10):
    """Append status message to log file with timestamp and automatic rotation

    Args:
        message: Status message to log
        log_file: Path to log file (default: hunt_status.log in current dir)
        max_size_mb: Maximum log file size in MB before rotation (default: 10)
    """
    timestamp = datetime.now().isoformat()
    log_path = Path(log_file)

    try:
        # Check if rotation needed
        if log_path.exists():
            size_mb = log_path.stat().st_size / (1024 * 1024)
            if size_mb > max_size_mb:
                # Rotate log
                backup_name = f"{log_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{log_path.suffix}"
                backup_path = log_path.parent / backup_name
                log_path.rename(backup_path)
                print(f"Log rotated: {backup_path}")

        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(f"{timestamp} | {message}\n")
    except Exception as e:
        # Silent failure - don't break workflow if logging fails
        print(f"Warning: Could not write to status log: {e}")
