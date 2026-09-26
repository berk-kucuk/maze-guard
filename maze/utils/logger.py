import logging
import os
import sys
from pathlib import Path


def setup_logger(name: str = "maze", level: int = logging.DEBUG) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    # File handler — persistent log. MAZE_GUARD_LOG_FILE overrides the path;
    # set to "" it turns the file off, which the test suite does so its mocked
    # failures ("firewalld stopped", "boom") never land in the user's real log.
    log_path = os.environ.get("MAZE_GUARD_LOG_FILE")
    try:
        if log_path is None:
            log_path = str(Path.home() / ".config" / "maze" / "maze.log")
        if not log_path:
            raise OSError("file logging disabled")
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=2 * 1024 * 1024,  # 2 MB
            backupCount=3,
            encoding="utf-8",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except Exception:
        pass

    logger.setLevel(level)
    return logger


import logging.handlers  # noqa: E402
log = setup_logger()
