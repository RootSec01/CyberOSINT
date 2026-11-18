from argparse import Namespace

from observatory.registry import OFFICIAL
from raqeeb import db, listings, manage
from raqeeb import models as m


def _entry(name, url):
    return {"server": {"name": name, "version": "1.0.0", "remotes": [{"type": "streamable-http", "url": url}]},
            "_meta": {OFFICIAL: {"status": "active", "isLatest": True}}}


ENTRIES = [_entry("org.alpha/search", "https://mcp.alpha.example.org/mcp"),
           _entry("org.alpha/other", "https://mcp.alpha.example.org/other"),
           _entry("org.beta/files", "https://beta.example.net/mcp"),
           _entry("org.gamma/private", "https://10.0.0.5/mcp")]


def test_registry_servers_are_added_one_per_host_with_a_listing_and_a_schedule(console, monkeypatch):
    monkeypatch.setattr(listings, "fetcher", lambda: lambda params: {"servers": ENTRIES})
    monkeypatch.setattr(listings, "public_address", lambda host: not host.startswith("10."))
    manage.cmd_add_registry(Namespace(owner="rami", count=5, every=360, seed="test"))
    manage.cmd_add_registry(Namespace(owner="rami", count=5, every=360, seed="test"))
    with db.session_scope() as session:
        assets = session.query(m.Asset).order_by(m.Asset.value).all()
        hosts = {a.value.split("/")[2] for a in assets}
        assert len(assets) == 2 and hosts == {"mcp.alpha.example.org", "beta.example.net"}
        assert session.query(m.Listing).count() == 2
        assert {s.every_minutes for s in session.query(m.Schedule)} == {360}
        assert session.query(m.AuditEntry).filter_by(action="registry_server_added").count() == 2


def test_the_sample_is_not_alphabetical_and_skips_personal_tunnels(console, monkeypatch):
    many = [_entry(f"org.n{i}/s", f"https://{chr(97 + i % 26)}{i}.example.org/mcp") for i in range(60)]
    many.append(_entry("dev.tunnel/s", "https://abc123.lhr.life/mcp"))
    monkeypatch.setattr(listings, "fetcher", lambda: lambda params: {"servers": many})
    monkeypatch.setattr(listings, "public_address", lambda host: True)
    manage.cmd_add_registry(Namespace(owner="rami", count=10, every=360, seed="test"))
    with db.session_scope() as session:
        values = [a.value for a in session.query(m.Asset).order_by(m.Asset.id)]
    every = sorted(f"https://{chr(97 + i % 26)}{i}.example.org/mcp" for i in range(60))
    assert len(values) == 10 and values != every[:10]
    assert not any("lhr.life" in v for v in values)


def test_registry_servers_can_all_be_removed_again(console, monkeypatch):
    monkeypatch.setattr(listings, "fetcher", lambda: lambda params: {"servers": ENTRIES})
    monkeypatch.setattr(listings, "public_address", lambda host: not host.startswith("10."))
    manage.cmd_add_registry(Namespace(owner="rami", count=5, every=360, seed="test"))
    with db.session_scope() as session:
        rami = session.query(m.User).filter_by(username="rami").one()
        session.add(m.Asset(user_id=rami.id, kind="mcp", value="127.0.0.1:9", label="kept"))
    manage.cmd_remove_registry(Namespace(owner="rami"))
    with db.session_scope() as session:
        assert [a.label for a in session.query(m.Asset)] == ["kept"]
        assert session.query(m.Listing).count() == 0 and session.query(m.Schedule).count() == 0
        assert session.query(m.AuditEntry).filter_by(action="registry_server_removed").count() == 2
