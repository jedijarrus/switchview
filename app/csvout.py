"""CSV downloads (Phase 4b): the history export (Task 3) and the audit export (Task 8). Without a route of its own.

The file opens as it is in Excel with German settings: ";" between the cells, UTF-8 with a BOM, CRLF at the end of each line, a
cell quoted only where it has to be (a ";", a quote or a line break in it). Text from the data (a device name, a port description)
can start like a formula; a cell that starts with one of FORMULA gets a "'" before it, so a spreadsheet shows it as text (OWASP CSV
injection; a leading line feed is quoted as well).
"""
import csv
import io
from collections.abc import Iterable
from datetime import datetime, timezone

from fastapi import Response

FORMULA = ("=", "+", "-", "@", "\t", "\r", "\n")    # the first characters a spreadsheet may read as the start of a formula


def cell(value) -> str:
    """value as the text of a cell: "" for None, else str(value), with a "'" before it when it starts with one of FORMULA."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(FORMULA) else text


def render(header: list[str], rows: Iterable[Iterable]) -> str:
    """The CSV text of header and rows, each cell through cell, with the BOM in front."""
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow([cell(v) for v in header])
    writer.writerows([cell(v) for v in row] for row in rows)
    return "\ufeff" + buf.getvalue()


def response(text: str, stem: str) -> Response:
    """text as a download named <stem>-<today's date in UTC>.csv."""
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return Response(content=text, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{stem}-{day}.csv"'})
