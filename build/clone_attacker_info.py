#!/usr/bin/env python3
"""Clone generic attacker-info break tests across all local break-it teams.

The attacker-info folder contains attacks filed against CPSLO-108.  Some are
generic fresh-DB correctness/crash probes and can be turned around against other
teams by changing target_team.  Others are CPSLO-specific confidentiality,
integrity, or exploit notes and should not be blindly cloned.
"""
import argparse
import json
import os
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTACKER_INFO = ROOT / "attacker-info"
BREAK_IT = ROOT / "break-it-code"
BREAK = ROOT / "break"


TEAM_SLUGS = {
    "0xwizards": "wizards",
    "GreatTeam26": "greatteam26",
    "GT": "GT",
    "Husker_Bots": "husker",
    "SMK": "SMK",
    "TPT_Enterprise": "tpt",
    "UW_Tacoma": "uw",
    "jojo": "jojo",
    "kevwjin": "kevwjin",
    "sensodyne": "sensodyne",
    "via": "via",
}


# One canonical source per generic class.  Rejected CPSLO submissions are still
# useful as probes against other teams, but exact duplicate CPSLO attempts are not.
GENERIC_ATTACKS = [
    {
        "slug": "create-no-user",
        "source": "1113-create_no_user",
        "aliases": ["create-no-user"],
    },
    {
        "slug": "register-no-key",
        "source": "1116-register_no_key",
        "aliases": ["register-no-key"],
    },
    {
        "slug": "duplicate-create",
        "source": "596-correctness-cpslo-dup-create",
        "aliases": ["duplicate-create", "dup-create", "create-existing-file"],
    },
    {
        "slug": "empty-filename",
        "source": "885-team108_empty_filename",
        "aliases": ["empty-filename", "empty-file"],
    },
    {
        "slug": "empty-key",
        "source": "598-correctness-cpslo-empty-key",
        "aliases": ["empty-key"],
    },
    {
        "slug": "empty-username",
        "source": "599-correctness-cpslo-empty-user",
        "aliases": ["empty-username", "empty-user"],
    },
    {
        "slug": "create-extra-positional",
        "source": "884-team108_create_extra_positional",
        "aliases": ["create-extra-positional"],
    },
    {
        "slug": "corrupt-db",
        "source": "888-team108_huge_blob_length",
        "aliases": ["corrupt-db", "huge-blob-length"],
    },
    {
        "slug": "fifo-hang",
        "source": "891-team108_input_file_fifo_timeout",
        "aliases": ["fifo-hang"],
    },
    {
        "slug": "long-filename",
        "source": "978-correctness-long-filename-CPSLO",
        "aliases": ["long-filename"],
    },
    {
        "slug": "long-key",
        "source": "979-correctness-long-key-CPSLO",
        "aliases": ["long-key"],
    },
    {
        "slug": "long-username",
        "source": "980-correctness-long-username-CPSLO",
        "aliases": ["long-username"],
    },
]


SKIPPED_ATTACKS = [
    "530-confidentiality-recover-CPSLO",
    "653-confidentiality-recover-CPSLO",
    "654-crash-dlmalloc-CPSLO",
    "655-integrity-forge-CPSLO",
    "656-security-shellcode-CPSLO",
    "953-cpslo108-integrity-empty-file",
    "987-confidentiality-recover-CPSLO",
]


def json_signature(test):
    body = {
        "type": test.get("type"),
        "commands": test.get("commands", []),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path, data):
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def discover_teams():
    teams = []
    for d in sorted(BREAK_IT.iterdir()):
        if not d.is_dir():
            continue
        m = re.match(r"(.+)-(\d+)$", d.name)
        if not m:
            continue
        team_name, team_id = m.group(1), int(m.group(2))
        teams.append((team_id, team_name, TEAM_SLUGS.get(team_name, team_name.lower())))
    return teams


def existing_index(attacks):
    by_team_class = {}
    by_team_sig = {}
    aliases = {
        attack["slug"]: [a.lower() for a in attack["aliases"]]
        for attack in attacks
    }

    for d in sorted(BREAK.iterdir() if BREAK.exists() else []):
        if not d.is_dir():
            continue
        test_path = d / "test.json"
        if not test_path.exists():
            continue
        try:
            test = load_json(test_path)
        except json.JSONDecodeError:
            continue
        team = test.get("target_team")
        if team is None:
            continue
        by_team_sig.setdefault(team, set()).add(json_signature(test))

        name = d.name.lower()
        for slug, names in aliases.items():
            if any(alias in name for alias in names):
                by_team_class.setdefault(team, set()).add(slug)

    return by_team_class, by_team_sig


def clone_one(attack, team, dry_run):
    team_id, _team_name, team_slug = team
    src_dir = ATTACKER_INFO / attack["source"]
    test = load_json(src_dir / "test.json")
    meta = load_json(src_dir / "break_meta.json")
    desc = (src_dir / "description.txt").read_text(encoding="utf-8")

    cloned = dict(test)
    cloned["target_team"] = team_id

    out_dir = BREAK / f"{team_slug}-{attack['slug']}"
    if dry_run:
        return out_dir

    out_dir.mkdir(parents=True, exist_ok=False)
    write_json(out_dir / "test.json", cloned)
    (out_dir / "description.txt").write_text(
        "\n".join(
            [
                f"{attack['slug']} — attacker-info turnaround targeting team {team_id} ({team_slug})",
                "",
                f"Origin: attacker-info/{attack['source']} "
                f"(submission {meta.get('submission_id')}, original result: {meta.get('result')}).",
                "This clone keeps the original command sequence and updates only target_team.",
                "",
                desc.rstrip(),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return out_dir


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    teams = discover_teams()
    by_team_class, by_team_sig = existing_index(GENERIC_ATTACKS)

    created = []
    skipped = []
    for attack in GENERIC_ATTACKS:
        base_test = load_json(ATTACKER_INFO / attack["source"] / "test.json")
        for team in teams:
            team_id = team[0]
            cloned = dict(base_test)
            cloned["target_team"] = team_id
            sig = json_signature(cloned)

            reason = None
            out_dir = BREAK / f"{team[2]}-{attack['slug']}"
            if attack["slug"] in by_team_class.get(team_id, set()):
                reason = "class already exists for team"
            elif sig in by_team_sig.get(team_id, set()):
                reason = "exact command duplicate already exists for team"
            elif out_dir.exists():
                reason = "output directory already exists"

            if reason:
                skipped.append((team_id, attack["slug"], reason))
                continue

            created_path = clone_one(attack, team, args.dry_run)
            created.append((team_id, attack["slug"], created_path))
            by_team_class.setdefault(team_id, set()).add(attack["slug"])
            by_team_sig.setdefault(team_id, set()).add(sig)

    manifest = BREAK / "ATTACKER_INFO_CLONES.md"
    lines = [
        "# Attacker-Info Clone Manifest",
        "",
        "Generated by `build/clone_attacker_info.py`.",
        "",
        "## Created",
        "",
    ]
    if created:
        lines += ["| Target | Attack | Path |", "|---:|---|---|"]
        for team_id, slug, path in created:
            lines.append(f"| {team_id} | {slug} | `{path.relative_to(ROOT)}` |")
    else:
        lines.append("No new clones created.")

    lines += [
        "",
        "## Skipped Existing Duplicates",
        "",
    ]
    if skipped:
        lines += ["| Target | Attack | Reason |", "|---:|---|---|"]
        for team_id, slug, reason in skipped:
            lines.append(f"| {team_id} | {slug} | {reason} |")
    else:
        lines.append("No duplicate skips.")

    lines += [
        "",
        "## Skipped Non-Generic Attacker-Info Items",
        "",
    ]
    for item in SKIPPED_ATTACKS:
        lines.append(f"- `attacker-info/{item}`")
    lines.append("")

    if args.dry_run:
        print("\n".join(lines))
    else:
        manifest.write_text("\n".join(lines), encoding="utf-8")
        print(f"created={len(created)} skipped_duplicates={len(skipped)} manifest={manifest.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
