from typing import Optional

import typer

from bomsquad.vulndb.db.ingest import Ingest
from bomsquad.vulndb.db.nvddb import NVDDB

nvd_app = typer.Typer(name="nvd")
osv_app = typer.Typer(name="osv")


@nvd_app.command(name="ingest")
def _nvd_ingest(
    scope: Optional[str] = typer.Option(default=None, help="Ingest only cve or cpe "),
    update: bool = typer.Option(default=False, help="Acquire records newer than current data"),
) -> None:
    db = NVDDB()
    if scope == "cve" or scope is None:
        # Update the existing records
        Ingest.cve(offset=0, last_mod_start_date=db.cve_last_modified() if update else None)
        # Acquire new records
        Ingest.cve(offset=db.cve_count() if update else 0)
    if scope == "cpe" or scope is None:
        # Update the existing records
        Ingest.cpe(offset=0, last_mod_start_date=db.cpe_last_modified() if update else None)
        # Acquire new records
        Ingest.cpe(offset=db.cpe_count() if update else 0)


@osv_app.command(name="ingest")
def _osv_ingest(
    ecosystem: Optional[str] = typer.Option(default=None, help="Ingest only a single ecosystem"),
    offset: int = typer.Option(default=0, help="Offset into available entries to begin wtih"),
    limit: Optional[int] = typer.Option(default=None, help="Limit the number of entries to ingest"),
) -> None:
    if ecosystem:
        Ingest.osv(ecosystem, offset, limit)
    else:
        if offset != 0 or limit:
            raise ValueError("Offset and limit are only valid with a specific ecosystem")
        Ingest.all_osv()
