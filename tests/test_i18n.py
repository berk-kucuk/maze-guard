"""
Translation-table invariants.

Two languages drift the moment one of them is edited alone, and a missing key
does not raise — it renders the key itself into the interface, which looks like
a bug in the security tool rather than a gap in a table. These tests make that
a test failure instead of a screenshot.

    ./venv/bin/python -m unittest discover -s tests -v
"""
import os
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("MAZE_GUARD_LOG_FILE", "")  # never write the real ~/.config/maze/maze.log
from maze.core.events import EventType, ThreatLevel        # noqa: E402
from maze.core.explain import EXPLAINED, keys_for          # noqa: E402
from maze.core.profile import Profile                      # noqa: E402
from maze.gui.i18n import STRINGS, t                       # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
_KEY_RE = re.compile(r"""\bt\(\s*["']([a-z0-9_]+)["']\s*\)""")


class TranslationTableTests(unittest.TestCase):
    def test_the_languages_hold_the_same_keys(self):
        self.assertEqual(set(STRINGS["en"]) ^ set(STRINGS["tr"]), set())

    def test_nothing_is_left_untranslated_by_accident(self):
        """A Turkish value identical to the English one is usually a copy that
        was never translated. Genuine identities (proper nouns, protocol
        names) are listed here so the check stays meaningful."""
        allowed = {
            "profile_paranoid", "col_ip", "col_mac", "col_hostname",
            "col_process", "col_pid", "dash_process", "dash_port",
            "dash_rule", "module_arp_watch", "dev_model", "dev_risk",
            "threats_score", "dash_vpn", "tab_firewall",
            "verify_btn", "dash_ip", "dash_mac",
        }
        same = [k for k, v in STRINGS["en"].items()
                if STRINGS["tr"].get(k) == v and k not in allowed]
        self.assertEqual(same, [], f"untranslated: {same}")

    def test_every_key_has_a_non_empty_value(self):
        for lang, table in STRINGS.items():
            empty = [k for k, v in table.items() if not str(v).strip()]
            self.assertEqual(empty, [], f"{lang}: {empty}")

    def test_an_unknown_key_is_returned_verbatim(self):
        self.assertEqual(t("no_such_key"), "no_such_key")


class CoverageTests(unittest.TestCase):
    def test_every_event_type_can_be_named(self):
        for kind in EventType:
            for lang in STRINGS:
                self.assertIn(f"threat_{ThreatLevel.SAFE.value}", STRINGS[lang])

    def test_every_explained_event_has_both_sentences(self):
        for kind in EXPLAINED:
            for key in keys_for(kind):
                for lang in STRINGS:
                    self.assertIn(key, STRINGS[lang], f"{lang}: {key}")

    def test_every_profile_has_a_label(self):
        for profile in Profile:
            for lang in STRINGS:
                self.assertIn(f"profile_{profile.value}", STRINGS[lang])

    def test_keys_used_by_the_interface_exist(self):
        """Scans the widgets for t("…") calls. A key that only appears at
        runtime — in a branch nobody exercised — would otherwise reach a user
        as a raw identifier."""
        missing = {}
        for path in (ROOT / "maze" / "gui").rglob("*.py"):
            for key in _KEY_RE.findall(path.read_text(encoding="utf-8")):
                if key not in STRINGS["en"]:
                    missing.setdefault(path.name, set()).add(key)
        self.assertEqual(missing, {}, f"undefined translation keys: {missing}")


if __name__ == "__main__":
    unittest.main()
