"""Live sources. `enrich` iterates `SOURCE_MODULES` and calls `.collect` on each
at run time (so tests can monkeypatch a module's `collect`)."""

from src.live.sources import epss, kev, nvd, osv

SOURCE_MODULES = (("osv", osv), ("nvd", nvd), ("kev", kev), ("epss", epss))

__all__ = ["SOURCE_MODULES", "epss", "kev", "nvd", "osv"]
