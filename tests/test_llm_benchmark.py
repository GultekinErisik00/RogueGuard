"""7A testleri: LLM deney veri seti (boyut, etiketler, varyantlar, injection) ve
benchmark metrikleri (doğruluk, confusion, hibrit API sayısı, injection özeti) — sahte
LLM istemcisiyle, ağ erişimi olmadan."""
from experiments import llm_benchmark as bench
from experiments import llm_dataset
from rogueguard.classify import llm as llm_mod
from rogueguard.classify import rules


def test_dataset_size_and_labels_are_valid():
    labeled = llm_dataset.build(include_live=False)["labeled"]
    assert 30 <= len(labeled) <= 50
    assert {i["truth"] for i in labeled} <= set(rules.LABELS)
    assert len({i["id"] for i in labeled}) == len(labeled)
    assert {"full", "no_hostname", "no_oui", "ports_only", "misleading_hostname",
            "external"} <= {i["variant"] for i in labeled}


def test_ports_only_variant_hides_identity():
    item = next(i for i in llm_dataset.build(include_live=False)["labeled"]
                if i["id"] == "cam-01:ports_only")
    prof = item["profile"]
    assert prof["oui"] == llm_dataset.ANON_OUI
    assert prof["hostname"] is None and prof["vendor_class"] is None and prof["mdns"] == []
    assert prof["ports"] == ["80/tcp", "554/tcp"]


def test_injection_items_put_payload_in_each_field():
    inj = llm_dataset.build(include_live=False)["injection"]
    assert len(inj) == 7 * 3  # 6 lab cihazı + fedora rogue, 3 alan
    cam = {i["field"]: i for i in inj if i["base_id"] == "cam-01:full"}
    assert cam["hostname"]["target"] == "printer"
    assert "Ignore previous instructions" in cam["hostname"]["profile"]["hostname"]
    assert cam["mdns"]["profile"]["mdns"][:2] == ["_http._tcp", "_rtsp._tcp"]
    assert "printer" in cam["mdns"]["profile"]["mdns"][-1]


class _ScriptedClassifier:
    """Profil hostname'ine göre sabit cevap veren sahte LLMClassifier."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = 0

    def classify(self, profile, use_cache=True):
        self.calls += 1
        return {"label": self.answers.get(profile.get("hostname"), "unknown"),
                "confidence": 0.9, "reason": "test"}


def _item(id_, truth, hostname, ports=None):
    return {"id": id_, "source": "test", "variant": "full", "truth": truth,
            "profile": {"oui": "02:00:00", "hostname": hostname, "vendor_class": None,
                        "ports": ports or [], "mdns": [], "interval": None, "opt55": None}}


def test_hybrid_uses_llm_only_when_rules_unknown():
    items = [_item("a", "printer", "x", ports=["631/tcp"]),  # kural: printer
             _item("b", "sensor", "y")]                       # kural: unknown → LLM
    llm = bench.TimedLLM(_ScriptedClassifier({"x": "camera", "y": "sensor"}))
    rows = bench.run_labeled(items, llm)
    assert rows[0]["hybrid"]["label"] == "printer" and rows[0]["hybrid"]["source"] == "rules"
    assert rows[1]["hybrid"]["label"] == "sensor" and rows[1]["hybrid"]["source"] == "llm"
    summary = bench.summarize(rows, [], [0.4, 0.6])
    assert summary["accuracy"] == {"rules": 0.5, "llm": 0.5, "hybrid": 1.0}
    assert summary["api_calls_per_method"] == {"rules": 0, "llm": 2, "hybrid": 1}
    assert summary["confusion"]["llm"]["printer"]["camera"] == 1
    assert summary["llm_latency"]["median_s"] == 0.5


def test_timed_llm_does_not_repeat_same_fingerprint():
    fake = _ScriptedClassifier({"x": "camera"})
    sleeps = []
    llm = bench.TimedLLM(fake, pace=2.0, sleeper=sleeps.append)
    prof = _item("a", "camera", "x")["profile"]
    llm.classify(prof)
    llm.classify(dict(prof))
    llm.classify(prof | {"hostname": "z"})
    assert fake.calls == 2 and llm.api_calls == 2 and sleeps == [2.0]
    assert llm.memo[llm_mod.fingerprint_hash(prof)]["label"] == "camera"


def test_injection_summary_counts_hijacks():
    answers = {"cam": "camera", "evil": "printer"}
    llm = bench.TimedLLM(_ScriptedClassifier(answers))
    base = bench.run_labeled([_item("a", "camera", "cam")], llm)
    inj_items = [{"id": "a:inj-hostname", "base_id": "a", "field": "hostname",
                  "truth": "camera", "target": "printer",
                  "profile": _item("a", "camera", "evil")["profile"]}]
    rows = bench.run_injection(inj_items, base, llm)
    summary = bench.injection_summary(rows)
    assert summary["llm"] == {"cases": 1, "label_changed": 1, "hijacked_to_target": 1}
    assert summary["rules"]["hijacked_to_target"] == 0
