"""Phase 5 Task 1: the fonts come from SwitchView itself (app/static/fonts, SIL OFL 1.1), index.html and app.css name no external
origin, and every static file answers a matching If-None-Match with 304."""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
INDEX = (STATIC / "index.html").read_text(encoding="utf-8")
CSS = (STATIC / "app.css").read_text(encoding="utf-8")
FONTS = {"Geist-Regular.woff2": ("Geist", "400"), "Geist-Medium.woff2": ("Geist", "500"), "Geist-SemiBold.woff2": ("Geist", "600"),
         "GeistMono-Regular.woff2": ("Geist Mono", "400"), "GeistMono-Medium.woff2": ("Geist Mono", "500")}


def test_index_and_css_name_no_external_origin():
    for text in (INDEX, CSS):
        assert not re.search(r"(?:https?:)?//[\w-]+(?:\.[\w-]+)+", text)
    assert "preconnect" not in INDEX


def test_every_font_face_is_a_local_woff2_with_swap():
    faces = {}
    for body in re.findall(r"@font-face\s*\{([^}]*)\}", CSS):
        prop = {k: v.strip() for k, v in re.findall(r"([\w-]+)\s*:\s*([^;]+);", body)}
        file = re.fullmatch(r'url\("/static/fonts/([\w.\-]+)"\) format\("woff2"\)', prop["src"])[1]
        assert (prop["font-display"], prop["font-style"]) == ("swap", "normal") and (STATIC / "fonts" / file).is_file()
        faces[file] = (prop["font-family"].strip('"'), prop["font-weight"])
    assert faces == FONTS


def test_the_fonts_are_served(login_api):
    for name in FONTS:
        r = login_api.get(f"/static/fonts/{name}")
        assert (r.status_code, r.headers["content-type"], r.headers["cache-control"]) == (200, "font/woff2", "no-cache")
        assert r.content == (STATIC / "fonts" / name).read_bytes() and r.content[:4] == b"wOF2" and r.headers["etag"]


@pytest.mark.parametrize("path", ["/static/fonts/OFL.txt", "/static/fonts/app.css", "/static/fonts/..%2Fapp.css", "/static/fonts/nope.woff2",
                                  "/static/OFL.txt", "/static/Geist-Regular.woff2"])
def test_the_font_route_serves_only_its_woff2_files(login_api, path):
    assert login_api.get(path).status_code == 404


@pytest.mark.parametrize("path", ["/static/app.css", "/static/sv-core.js", "/static/favicon.svg", "/static/fonts/Geist-Regular.woff2"])
def test_a_static_file_answers_304_to_its_etag(login_api, path):
    first = login_api.get(path)
    etag = first.headers["etag"]
    again = login_api.get(path, headers={"If-None-Match": etag})
    assert (again.status_code, again.content, again.headers["etag"], again.headers["cache-control"]) == (304, b"", etag, "no-cache")
    assert login_api.get(path, headers={"If-None-Match": f'"x", W/{etag}'}).status_code == 304
    assert login_api.get(path, headers={"If-None-Match": '"other"'}).status_code == 200


def test_the_font_license_ships_with_the_fonts():
    text = (STATIC / "fonts" / "OFL.txt").read_text(encoding="utf-8")
    assert "SIL Open Font License" in text and "Version 1.1" in text
    assert "SIL Open Font License" in (ROOT / "README.md").read_text(encoding="utf-8")
