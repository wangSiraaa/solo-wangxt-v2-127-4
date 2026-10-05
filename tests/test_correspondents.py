"""Correspondent index: parse-phase extraction, per-role counts, defects.

Covers the archival "organize by correspondent" workflow:
* same mailbox counted separately in From/To(/Cc) roles
* case and display-name variants folded into one mailbox
* encoded (Chinese) display names traceable to the raw header
* malformed addresses visible as defects, never disguised as contacts
* no contacts inferred from subjects; search/threads unaffected
"""
from __future__ import annotations

from conftest import SAMPLES


def _eml(
    *,
    from_: str | None = None,
    to: str | None = None,
    cc: str | None = None,
    subject: str = "correspondent test",
    message_id: str | None = None,
) -> bytes:
    lines = []
    if message_id:
        lines.append(f"Message-ID: <{message_id}>")
    if from_ is not None:
        lines.append(f"From: {from_}")
    if to is not None:
        lines.append(f"To: {to}")
    if cc is not None:
        lines.append(f"Cc: {cc}")
    lines.append(f"Subject: {subject}")
    lines.append("Content-Type: text/plain")
    return ("\r\n".join(lines) + "\r\n\r\nbody\r\n").encode()


def _post(client, data: bytes, name: str = "t.eml", **params):
    return client.post("/ingest", files={"file": (name, data, "message/rfc822")}, params=params)


def test_sender_and_recipient_counted_separately(client):
    c, _ = client
    _post(c, _eml(from_="Alice@Example.COM", to="bob@example.com", message_id="m1@x"))
    _post(c, _eml(from_="bob@example.com", to="alice@example.com", message_id="m2@x"))

    r = c.get("/correspondents/alice@example.com")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["from_count"] == 1
    assert d["to_count"] == 1
    assert d["cc_count"] == 0
    assert d["sender_count"] == 1
    assert d["recipient_count"] == 1
    assert d["message_count"] == 2
    assert len(d["messages"]) == 2

    # lookup is case-insensitive: same mailbox, any spelling
    again = c.get("/correspondents/ALICE@EXAMPLE.COM")
    assert again.status_code == 200
    assert again.json()["address"] == "alice@example.com"
    assert again.json()["from_count"] == 1

    # bob is sender once, recipient once
    bob = c.get("/correspondents/bob@example.com").json()
    assert (bob["from_count"], bob["to_count"]) == (1, 1)

    listing = {row["address"] for row in c.get("/correspondents").json()}
    assert listing == {"alice@example.com", "bob@example.com"}


def test_case_and_display_name_variants_grouped(client):
    c, _ = client
    _post(c, _eml(from_='"Alice A" <alice@example.com>', message_id="v1@x"))
    _post(c, _eml(from_='"A. Alice" <ALICE@example.com>', message_id="v2@x"))

    listing = c.get("/correspondents").json()
    alice = [row for row in listing if row["address"] == "alice@example.com"]
    assert len(alice) == 1, "variants must fold into one mailbox"
    assert alice[0]["from_count"] == 2
    assert alice[0]["display_names"] == ["A. Alice", "Alice A"]

    detail = c.get("/correspondents/alice@example.com").json()
    # original spelling preserved per occurrence
    raws = {s["address_raw"] for m in detail["messages"] for s in m["sources"]}
    assert raws == {"alice@example.com", "ALICE@example.com"}


def test_chinese_display_name_traceable(client):
    c, _ = client
    r = _post(c, (SAMPLES / "01_multibyte.eml").read_bytes(), "01_multibyte.eml")
    assert r.status_code == 201

    d = c.get("/correspondents/cn@example.com").json()
    assert d["to_count"] == 1 and d["from_count"] == 0
    # RFC2047 gb18030 display name decoded for search/display...
    assert "【点名册】" in d["display_names"]
    # ...and the original encoded header kept for forensics
    src = d["messages"][0]["sources"][0]
    assert src["header_name"] == "To"
    assert "=?gb18030?b?ob6148P7suGhvw==?=" in src["raw_header"]

    sigs = c.get("/correspondents/sigs@example.com").json()
    assert sigs["from_count"] == 1
    assert any(name.startswith("老王") for name in sigs["display_names"])
    assert "=?utf-8?b?" in sigs["messages"][0]["sources"][0]["raw_header"]


def test_malformed_address_is_defect_not_contact(client):
    c, _ = client
    r = _post(c, _eml(from_="not-an-address", to="ok@example.com", message_id="bad@x"))
    assert r.status_code == 201
    assert r.json()["status"] == "defective"

    # bad token never becomes a contact
    assert c.get("/correspondents/not-an-address").status_code == 404
    listing = {row["address"] for row in c.get("/correspondents").json()}
    assert listing == {"ok@example.com"}

    # ...but stays queryable as a defect, located at the From header
    ingest_id = r.json()["ingest_id"]
    detail = c.get(f"/ingests/{ingest_id}").json()
    bad = [d for d in detail["defects"] if d["level"] == "InvalidAddress"]
    assert bad and bad[0]["stage"] == "0:from"
    assert "not-an-address" in bad[0]["message"]

    fails = c.get("/failures").json()
    assert any(
        d["level"] == "InvalidAddress" and "not-an-address" in d["message"]
        for f in fails
        for d in f["defects"]
    )


def test_unparseable_header_and_empty_address_defects(client):
    c, _ = client
    # nothing parseable at all, and an empty < > address
    r = _post(c, _eml(from_="a@b c@d", to="bob <>", message_id="bad2@x"))
    assert r.json()["status"] == "defective"
    ingest_id = r.json()["ingest_id"]
    defects = c.get(f"/ingests/{ingest_id}").json()["defects"]
    stages = {d["stage"] for d in defects if d["level"] == "InvalidAddress"}
    assert stages == {"0:from", "0:to"}
    assert c.get("/correspondents").json() == []


def test_empty_group_is_not_a_defect(client):
    c, _ = client
    r = _post(c, _eml(from_="a@example.com", to="undisclosed-recipients:;", message_id="grp@x"))
    assert r.json()["status"] == "ok"
    listing = {row["address"] for row in c.get("/correspondents").json()}
    assert listing == {"a@example.com"}


def test_no_contacts_inferred_from_subject(client):
    c, _ = client
    _post(
        c,
        _eml(
            from_="carol@example.com",
            subject="Please loop in bob@example.com and dave@example.com",
            message_id="subj@x",
        ),
    )
    assert c.get("/correspondents/bob@example.com").status_code == 404
    assert c.get("/correspondents/dave@example.com").status_code == 404
    listing = {row["address"] for row in c.get("/correspondents").json()}
    assert listing == {"carol@example.com"}


def test_detail_lists_roles_and_source_headers(client):
    c, _ = client
    _post(
        c,
        _eml(
            from_="Alice <alice@example.com>",
            to="alice@example.com",
            cc="Other <other@example.com>",
            message_id="roles@x",
        ),
    )
    d = c.get("/correspondents/alice@example.com").json()
    assert d["message_count"] == 1
    msg = d["messages"][0]
    assert msg["roles"] == ["from", "to"]
    by_header = {s["header_name"]: s for s in msg["sources"]}
    assert set(by_header) == {"From", "To"}
    assert by_header["From"]["raw_header"].startswith("Alice <alice@example.com>")
    assert by_header["From"]["display_name"] == "Alice"
    assert by_header["To"]["display_name"] == ""


def test_unknown_correspondent_is_404(client):
    c, _ = client
    assert c.get("/correspondents/never-seen@example.com").status_code == 404


def test_search_and_threads_unaffected(client):
    c, _ = client
    for n in ["02_cycle_a.eml", "02_cycle_b.eml"]:
        _post(c, (SAMPLES / n).read_bytes(), n, recompute_threads=False)
    _post(c, _eml(from_="not-an-address", to="ok@example.com", subject="findme-unique"))

    rebuilt = c.post("/threads/rebuild").json()
    flat_cycles = {x for cyc in rebuilt["cycles"] for x in cyc}
    assert {"cycle-a@example.com", "cycle-b@example.com"} <= flat_cycles

    hits = c.get("/search", params={"q": "findme-unique"}).json()
    assert hits["count"] == 1
    # bad address is not a contact but the header text is still searchable
    assert c.get("/search", params={"q": "not-an-address"}).json()["count"] == 1
