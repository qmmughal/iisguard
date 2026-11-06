from __future__ import annotations

from pathlib import Path

import pytest

import synth
from iisguard.analyzer import Analyzer, Report
from iisguard.config import Config
from iisguard.firewall.safety import Protector
from iisguard.logs import iter_events
from iisguard.models import ParseStats
from iisguard.rules import RuleSet, load_rules


@pytest.fixture(scope="session")
def logs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    d = tmp_path_factory.mktemp("logs")
    clean, attack = synth.clean_events(), synth.attack_events()
    both = sorted(clean + attack)
    out = {
        "clean_iis": d / "clean_iis.log",
        "clean_nginx": d / "clean_nginx.log",
        "attack_iis": d / "attack_iis.log",
        "attack_nginx": d / "attack_nginx.log",
        "attack_apache": d / "attack_apache.log",
        "attack_json": d / "attack_json.log",
        "php_error": d / "php_error.log",
        "apache_error": d / "apache_error.log",
    }
    synth.write_iis(out["clean_iis"], clean)
    synth.write_combined(out["clean_nginx"], clean)
    synth.write_iis(out["attack_iis"], both)
    synth.write_combined(out["attack_nginx"], both)
    synth.write_combined(out["attack_apache"], both, tz="+0200")
    synth.write_json(out["attack_json"], both)
    out["php_error"].write_text("\n".join(synth.php_error_lines()) + "\n")
    out["apache_error"].write_text("\n".join(synth.apache_error_lines()) + "\n")
    return out


def run_scan(paths: list[Path], protector: Protector | None = None, cfg: Config | None = None) -> Report:
    cfg = cfg or Config()
    an = Analyzer(RuleSet(load_rules()), cfg, protector or Protector())
    stats = ParseStats()
    for p in paths:
        for ev in iter_events(str(p), "auto", stats):
            an.feed(ev)
    return an.finish()
