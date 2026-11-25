"""6.7 testleri: kural tabanlı ve LLM (Groq) cihaz türü sınıflandırma — 6 lab profili,
JSON ayrıştırma, parmak izi hash önbelleği, 429 retry-after ve hibrit yedekleme."""
from types import SimpleNamespace
import yaml

from rogueguard import config
from rogueguard.classify import llm as llm_mod
from rogueguard.classify import rules
from rogueguard.fingerprint import profile


def test_rules_classify_all_six_lab_profiles():
    spec = yaml.safe_load((config.ROOT / "lab/devices.yaml").read_text())["devices"]
    for name, dev in spec.items():
        prof = profile.build_from_spec(name, dev)
        res = rules.classify(prof)
        assert res["label"] == dev["type"], f"{name}: beklenen {dev['type']}, gelen {res}"
        assert res["confidence"] >= 0.7


def test_rules_returns_unknown_for_empty_profile():
    res = rules.classify({"oui": "aa:bb:cc", "hostname": None, "vendor_class": None,
                          "ports": [], "mdns": [], "interval": None})
    assert res["label"] == "unknown" and res["confidence"] == 0.0


def test_parse_llm_json_handles_fences_and_invalid_labels():
    res = llm_mod.parse_llm_json('```json\n{"label": "CAMERA", "confidence": 0.92, "reason": "rtsp"}\n```')
    assert res == {"label": "camera", "confidence": 0.92, "reason": "rtsp"}
    bad = llm_mod.parse_llm_json('{"label": "toaster", "confidence": 0.9, "reason": "x"}')
    assert bad["label"] == "unknown"


class _FakeCompletions:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=item))])


def _fake_client(responses):
    comp = _FakeCompletions(responses)
    return SimpleNamespace(chat=SimpleNamespace(completions=comp)), comp


def test_llm_classifier_caches_by_fingerprint_hash(tmp_path):
    client, comp = _fake_client(['{"label": "printer", "confidence": 0.88, "reason": "ipp"}'])
    cache_file = tmp_path / "cache.json"
    clf = llm_mod.LLMClassifier(client=client, cache_path=cache_file)
    prof = {"oui": "00:1b:a9", "hostname": "brn", "ports": ["631/tcp"], "mdns": ["_ipp._tcp"]}

    first = clf.classify(prof)
    second = clf.classify(prof)
    assert first["label"] == "printer" and first["cached"] is False
    assert second["label"] == "printer" and second["cached"] is True
    assert comp.calls == 1

    # Yeni örnek aynı önbellek dosyasını okur
    clf2 = llm_mod.LLMClassifier(client=client, cache_path=cache_file)
    assert clf2.get_cached(prof)["label"] == "printer"


def test_llm_classifier_retries_on_429_using_retry_after(tmp_path):
    class RateLimitError(Exception):
        status_code = 429
        response = SimpleNamespace(headers={"retry-after": "1.5"})

    sleeps = []
    client, comp = _fake_client([
        RateLimitError("rate limited"),
        '{"label": "sensor", "confidence": 0.81, "reason": "esp32"}',
    ])
    clf = llm_mod.LLMClassifier(client=client, cache_path=tmp_path / "c.json",
                                sleeper=sleeps.append)
    res = clf.classify({"oui": "00:4b:12", "hostname": "esp"})
    assert res["label"] == "sensor" and comp.calls == 2 and sleeps == [1.5]


def test_llm_without_api_key_returns_unknown_safely(tmp_path):
    clf = llm_mod.LLMClassifier(api_key="", cache_path=tmp_path / "c.json")
    assert not clf.enabled
    assert clf.classify({"oui": "00:00:00"})["label"] == "unknown"


def test_hybrid_uses_llm_only_when_rules_return_unknown(tmp_path):
    client, comp = _fake_client(['{"label": "smart_plug", "confidence": 0.8, "reason": "upnp"}'])
    clf = llm_mod.LLMClassifier(client=client, cache_path=tmp_path / "c.json")

    known = llm_mod.classify_hybrid({"oui": "00:40:8c", "ports": ["554/tcp"]}, clf)
    assert known["label"] == "camera" and known["source"] == "rules" and comp.calls == 0

    ambig = llm_mod.classify_hybrid({"oui": "aa:bb:cc", "hostname": "my-dev", "ports": ["80/tcp"]}, clf)
    assert ambig["label"] == "smart_plug" and ambig["source"] == "llm" and comp.calls == 1
