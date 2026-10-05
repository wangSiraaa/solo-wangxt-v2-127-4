"""Correspondent index: extraction, normalization, defects, and API queries."""
from app.parser import ParseStatus, parse_eml
from conftest import SAMPLES


def read_sample(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()


def _post(client, name, data, **params):
    return client.post(
        "/ingest",
        files={"file": (name, data, "message/rfc822")},
        params=params,
    )


# ---------- parser: extraction & normalization ----------

def test_correspondents_extracted_with_decoded_names_and_raw_headers():
    p = parse_eml(read_sample("01_multibyte.eml"))
    by_key = {(c.role, c.address): c for c in p.correspondents}
    assert set(by_key) == {
        ("from", "sigs@example.com"),
        ("to", "cn@example.com"),
        ("to", "jp@example.com"),
    }
    # RFC2047 display names decoded (gb18030 / iso-2022-jp / utf-8)
    assert by_key[("to", "cn@example.com")].display_name == "【点名册】"
    assert by_key[("from", "sigs@example.com")].display_name.startswith("老王")
    # raw encoded header kept for traceability
    assert "=?gb18030?b?" in by_key[("to", "cn@example.com")].raw_header
    # embedded message/rfc822 headers are NOT correspondents of this message
    assert all(c.address != "fwd@example.com" for c in p.correspondents)


def test_case_and_display_name_variants_share_one_mailbox():
    eml = (
        b"From: =?utf-8?q?Alice_L?= <Alice@Example.com>\r\n"
        b"To: \"A. Lice\" <alice@example.com>, ALICE@EXAMPLE.COM\r\n"
        b"Cc: alice@example.COM\r\n"
        b"Subject: x\r\n\r\nbody\r\n"
    )
    p = parse_eml(eml)
    assert p.status is ParseStatus.OK
    assert [(c.role, c.address) for c in p.correspondents] == [
        ("from", "alice@example.com"),
        ("to", "alice@example.com"),
        ("cc", "alice@example.com"),
    ]
    names = {c.display_name for c in p.correspondents}
    assert "Alice L" in names and "A. Lice" in names


def test_malformed_addresses_become_defects_not_correspondents():
    p = parse_eml(read_sample("10_correspondents.eml"))
    assert p.status is ParseStatus.DEFECTIVE
    indexed = {(c.role, c.address) for c in p.correspondents}
    assert ("from", "archivist@example.com") in indexed
    assert ("to", "archivist@example.com") in indexed
    assert ("cc", "archivist@example.com") in indexed
    assert ("to", "carol@example.com") in indexed
    # bad tokens are not disguised as valid addresses
    assert all("broken" not in c.address for c in p.correspondents)
    assert all("not-an-address" not in c.address for c in p.correspondents)
    bad = [d for d in p.defects if d.level == "MalformedAddress"]
    assert {d.stage for d in bad} == {"0:to", "0:cc"}
    assert any("broken@" in d.message for d in bad)
    assert any("not-an-address" in d.message for d in bad)


def test_poison_token_does_not_hide_valid_addresses():
    eml = b"To: @@, good@example.com, broken@\r\nSubject: x\r\n\r\nbody\r\n"
    p = parse_eml(eml)
    assert [(c.role, c.address) for c in p.correspondents] == [("to", "good@example.com")]
    bad = [d for d in p.defects if d.level == "MalformedAddress"]
    assert len(bad) == 2  # '@@' and 'broken@' both located


def test_group_syntax_and_empty_group():
    eml = (
        b"From: Team: lead@example.com, member@example.com;\r\n"
        b"To: undisclosed-recipients:;\r\n"
        b"Subject: x\r\n\r\nbody\r\n"
    )
    p = parse_eml(eml)
    assert p.status is ParseStatus.OK
    assert {(c.role, c.address) for c in p.correspondents} == {
        ("from", "lead@example.com"),
        ("from", "member@example.com"),
    }


def test_no_correspondent_inference_from_subject_or_body():
    eml = (
        b"From: real@example.com\r\n"
        b"Subject: please contact fake@example.com about this\r\n\r\n"
        b"or write to also-not-a-correspondent@example.com\r\n"
    )
    p = parse_eml(eml)
    assert [(c.role, c.address) for c in p.correspondents] == [("from", "real@example.com")]


# ---------- API: queryable correspondent index ----------

def test_correspondent_counts_per_role_and_detail(client):
    c, _ = client
    r = _post(c, "10_correspondents.eml", read_sample("10_correspondents.eml"))
    assert r.status_code == 201
    pk = r.json()["message_pk"]

    listing = {e["address"]: e for e in c.get("/correspondents").json()}
    arch = listing["archivist@example.com"]
    # same mailbox counted separately per role
    assert (arch["from_count"], arch["to_count"], arch["cc_count"], arch["total"]) == (1, 1, 1, 3)
    assert "档案员小李" in arch["display_names"]
    assert "Li (archivist)" in arch["display_names"]
    assert listing["carol@example.com"]["to_count"] == 1
    # malformed tokens never entered the index
    assert not any("broken" in a or "not-an-address" in a for a in listing)

    # lookup is case-insensitive; detail names role and source header
    detail = c.get("/correspondents/Archivist@Example.COM").json()
    assert detail["address"] == "archivist@example.com"
    roles = {(m["role"], m["message_pk"]) for m in detail["messages"]}
    assert roles == {("from", pk), ("to", pk), ("cc", pk)}
    from_entry = next(m for m in detail["messages"] if m["role"] == "from")
    # Chinese display name traceable to its raw encoded header
    assert from_entry["display_name"] == "档案员小李"
    assert "=?gb18030?b?" in from_entry["raw_header"]

    # role filter narrows the message list, counts stay global
    only_from = c.get("/correspondents/archivist@example.com", params={"role": "from"}).json()
    assert [m["role"] for m in only_from["messages"]] == ["from"]
    assert only_from["total"] == 3

    assert c.get("/correspondents/unknown@example.com").status_code == 404
    assert c.get("/correspondents/archivist@example.com", params={"role": "sender"}).status_code == 422


def test_correspondent_index_spans_messages(client):
    c, _ = client
    _post(c, "01_multibyte.eml", read_sample("01_multibyte.eml"))
    _post(c, "10_correspondents.eml", read_sample("10_correspondents.eml"))
    listing = {e["address"]: e for e in c.get("/correspondents").json()}
    assert listing["sigs@example.com"]["from_count"] == 1
    assert listing["cn@example.com"]["to_count"] == 1
    detail = c.get("/correspondents/cn@example.com").json()
    assert detail["messages"][0]["subject"] == "多编码测试 — éπü"


def test_bad_addresses_visible_in_failures(client):
    c, _ = client
    r = _post(c, "10_correspondents.eml", read_sample("10_correspondents.eml"))
    assert r.json()["status"] == "defective"
    fails = c.get("/failures").json()
    mine = next(f for f in fails if f["ingest_id"] == r.json()["ingest_id"])
    bad = [d for d in mine["defects"] if d["level"] == "MalformedAddress"]
    assert len(bad) == 2
    assert any("broken@" in d["message"] for d in bad)


def test_search_and_threads_unaffected_by_correspondent_index(client):
    c, _ = client
    _post(c, "01_multibyte.eml", read_sample("01_multibyte.eml"))
    _post(c, "10_correspondents.eml", read_sample("10_correspondents.eml"), recompute_threads=False)
    # old substring search behavior unchanged
    assert c.get("/search", params={"q": "multi-01@example.com"}).json()["count"] == 1
    assert c.get("/search", params={"q": "GB18030"}).json()["count"] >= 1
    # threading still driven only by Message-ID/References/In-Reply-To
    rebuilt = c.post("/threads/rebuild").json()
    assert rebuilt["messages"] == 2
    assert rebuilt["threads"] == 2  # no shared identity headers -> no merge
