#
#ARCHIVO EXCEL A GUARDAR MAC/IPS/NOMBRES/FABRICANTES/ESTADO
#


from __future__ import annotations

import datetime as _dt
import zipfile
from pathlib import Path
from typing import Iterable, Sequence

_CT = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>"""

_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""

_WORKBOOK = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="{name}" sheetId="1" r:id="rId1"/></sheets>
</workbook>"""

_WB_RELS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""

_STYLES = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
<borders count="1"><border/></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>
</styleSheet>"""

_ILLEGAL = {
    c: None for c in range(0x00, 0x20)
    if c not in (0x09, 0x0A, 0x0D)
}


def _escape(text: str) -> str:
    text = text.translate(_ILLEGAL)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )

#columans en el excel 0 -> A, 25 -> Z, 26 -> AA
def _col_name(index: int) -> str:
    name = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        name = chr(65 + rem) + name
    return name

#celdas en el ecxcel
def _cell(ref: str, value, bold: bool) -> str:
    style = ' s="1"' if bold else ""
    if value is None or value == "":
        return f'<c r="{ref}"{style}/>'
    if isinstance(value, bool):
        return f'<c r="{ref}"{style} t="b"><v>{1 if value else 0}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}"{style}><v>{value}</v></c>'
    if isinstance(value, (_dt.datetime, _dt.date)):
        value = value.isoformat(sep=" ") if isinstance(value, _dt.datetime) else value.isoformat()
    return (
        f'<c r="{ref}"{style} t="inlineStr"><is><t xml:space="preserve">'
        f"{_escape(str(value))}</t></is></c>"
    )


def _sheet_xml(rows: Sequence[Sequence[object]]) -> str:
    widths: list[int] = []
    for row in rows:
        for i, cell in enumerate(row):
            length = len(str(cell)) if cell is not None else 0
            if i >= len(widths):
                widths.append(length)
            else:
                widths[i] = max(widths[i], length)

    cols = "".join(
        f'<col min="{i + 1}" max="{i + 1}" width="{min(max(w + 2, 8), 60)}" customWidth="1"/>'
        for i, w in enumerate(widths)
    )

    body: list[str] = []
    for r, row in enumerate(rows, start=1):
        cells = "".join(
            _cell(f"{_col_name(c)}{r}", value, bold=(r == 1))
            for c, value in enumerate(row)
        )
        body.append(f'<row r="{r}">{cells}</row>')

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<cols>{cols}</cols>"
        f"<sheetData>{''.join(body)}</sheetData>"
        "</worksheet>"
    )


def write_xlsx(path: str | Path, rows: Iterable[Sequence[object]],
               sheet_name: str = "Devices") -> Path:

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = list(rows)
    sheet = _sheet_xml(rows)

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CT)
        zf.writestr("_rels/.rels", _RELS)
        zf.writestr("xl/workbook.xml", _WORKBOOK.format(name=_escape(sheet_name)[:31]))
        zf.writestr("xl/_rels/workbook.xml.rels", _WB_RELS)
        zf.writestr("xl/styles.xml", _STYLES)
        zf.writestr("xl/worksheets/sheet1.xml", sheet)
    return path
