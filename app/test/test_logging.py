"""
Tests for the logging section of the config and the rotating log file.
"""

import logging

import pytest
from pydantic import ValidationError

import app.util.logging_helper as logging_helper
from app.config.app_settings import LoggingSettings
from app.util.logging_helper import configure_logging, setup_logging

WATCHED_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access", "sqlalchemy.engine")


@pytest.fixture
def clean_logging(monkeypatch, tmp_path):
    """Gives each test unconfigured logging with tmp_path as the runtime directory, then restores the old state."""
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    saved = {name: (logging.getLogger(name).level, list(logging.getLogger(name).handlers)) for name in WATCHED_LOGGERS}
    monkeypatch.setattr(logging_helper, "_configured", False)
    monkeypatch.setattr(logging_helper, "get_runtime_path", lambda: str(tmp_path))
    yield tmp_path
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()
    for handler in saved_handlers:
        root.addHandler(handler)
    root.setLevel(saved_level)
    for name, (level, handlers) in saved.items():
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.handlers[:] = handlers


def _flush():
    for handler in logging.getLogger().handlers:
        handler.flush()


class TestSettings:
    def test_the_level_may_be_written_in_any_case(self):
        assert LoggingSettings(level="debug").level == "DEBUG"

    def test_an_unknown_level_is_refused(self):
        for level in ("verbose", "BASIC_FORMAT"):
            with pytest.raises(ValidationError):
                LoggingSettings(level=level)

    def test_an_empty_file_disables_file_logging(self):
        assert LoggingSettings(file="").file is None
        assert LoggingSettings(file="  ").file is None
        assert LoggingSettings(file=None).file is None

    def test_file_logging_is_on_by_default(self):
        assert LoggingSettings().file == "logs/kirov-server.log"


class TestLogFile:
    def test_a_relative_file_goes_in_the_runtime_directory(self, clean_logging):
        path = configure_logging(LoggingSettings(file="logs/server.log"))
        assert path == (clean_logging / "logs" / "server.log").resolve()
        logging.getLogger("app.test").info("hello file")
        _flush()
        assert "hello file" in path.read_text(encoding="utf-8")

    def test_uvicorn_records_reach_the_file(self, clean_logging):
        path = configure_logging(LoggingSettings(file="server.log"))
        logging.getLogger("uvicorn.error").info("bind failed")
        _flush()
        assert "bind failed" in path.read_text(encoding="utf-8")

    def test_no_file_without_a_path(self, clean_logging):
        assert configure_logging(LoggingSettings(file=None)) is None
        assert not list(clean_logging.iterdir())

    def test_logging_is_configured_once(self, clean_logging):
        assert configure_logging(LoggingSettings(file="first.log")) is not None
        assert configure_logging(LoggingSettings(file="second.log")) is None
        assert not (clean_logging / "second.log").exists()

    def test_a_second_setup_closes_the_first_file(self, clean_logging):
        setup_logging(log_file=clean_logging / "first.log")
        (first,) = [h for h in logging.getLogger().handlers if isinstance(h, logging.FileHandler)]
        setup_logging(log_file=clean_logging / "second.log")
        assert first.stream is None
        files = [h for h in logging.getLogger().handlers if isinstance(h, logging.FileHandler)]
        assert [h.baseFilename for h in files] == [str((clean_logging / "second.log").resolve())]

    def test_sql_statements_are_logged_only_when_asked(self, clean_logging):
        configure_logging(LoggingSettings(file=None))
        assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING
        setup_logging(sql=True)
        assert logging.getLogger("sqlalchemy.engine").level == logging.INFO
