"""Devin org assets the controller owns: five playbooks (one per work-item kind, each carrying its
structured-output schema) and one knowledge note.

The committed files under `playbooks/` and `knowledge/` are the source of truth. `AssetSyncer`
reconciles Devin with them: create what is missing, update what differs, touch nothing that already
matches, and record the resulting ids in `devin_assets` so the live orchestrator can pass
`playbook_id`/`knowledge_ids` on every session. A second sync against an unchanged tree makes no
write call at all, which is what "idempotent" means here and what the tests assert.

Playbook files start with a small front-matter block:

    ---
    kind: dependency_upgrade
    title: Dependency upgrade (kind 1)
    macro: !hl-dependency-upgrade
    ---
    <body markdown>

Knowledge files use `name`, `trigger` and optional `pinned_repo` instead of `kind`/`macro`."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from sqlalchemy.engine import Engine
from sqlmodel import Session, col, select

from hardening_loop.db import session_scope
from hardening_loop.devin.protocol import (
    DevinClient,
    NoteRecord,
    NoteUpsert,
    PlaybookRecord,
    PlaybookUpsert,
)
from hardening_loop.devin.schemas import schema_for
from hardening_loop.domain.enums import Kind
from hardening_loop.models.tables import DevinAsset, utcnow

PLAYBOOKS_DIR = "playbooks"
KNOWLEDGE_DIR = "knowledge"
SCHEMA_MAX_BYTES = 64 * 1024
_MACRO_RE = re.compile(r"^![A-Za-z0-9_-]+$")
_FRONT_MATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)

AssetKind = Literal["playbook", "knowledge"]


class AssetError(ValueError):
    pass


@dataclass(frozen=True)
class PlaybookSpec:
    slug: str
    kind: Kind
    upsert: PlaybookUpsert
    path: Path

    @property
    def content_sha256(self) -> str:
        return _digest(self.upsert.model_dump())


@dataclass(frozen=True)
class KnowledgeSpec:
    slug: str
    upsert: NoteUpsert
    path: Path

    @property
    def content_sha256(self) -> str:
        return _digest(self.upsert.model_dump())


@dataclass(frozen=True)
class AssetBundle:
    playbooks: dict[Kind, PlaybookSpec]
    knowledge: list[KnowledgeSpec]

    def playbook_by_slug(self) -> dict[str, PlaybookSpec]:
        return {p.slug: p for p in self.playbooks.values()}


def _digest(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _front_matter(path: Path) -> tuple[dict[str, str], str]:
    text = path.read_text(encoding="utf-8")
    m = _FRONT_MATTER_RE.match(text)
    if m is None:
        raise AssetError(f"{path}: missing front matter block")
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            raise AssetError(f"{path}: bad front matter line {line!r}")
        meta[key.strip()] = value.strip()
    body = m.group(2).strip("\n")
    if not body.strip():
        raise AssetError(f"{path}: empty body")
    return meta, body + "\n"


def load_assets(root: Path) -> AssetBundle:
    """Parse and validate every committed asset. Fails on a missing kind, a duplicate kind, a bad
    macro, or a schema over the documented 64KB limit; never returns a partial bundle."""
    playbooks: dict[Kind, PlaybookSpec] = {}
    pb_dir = root / PLAYBOOKS_DIR
    for path in sorted(pb_dir.glob("*.md")):
        meta, body = _front_matter(path)
        for key in ("kind", "title", "macro"):
            if key not in meta:
                raise AssetError(f"{path}: front matter needs `{key}`")
        try:
            kind = Kind[meta["kind"]]
        except KeyError:
            raise AssetError(f"{path}: unknown kind {meta['kind']!r}") from None
        if kind in playbooks:
            raise AssetError(f"{path}: kind {kind.name} already defined by {playbooks[kind].path}")
        if path.stem != kind.playbook_slug:
            raise AssetError(f"{path}: file must be named {kind.playbook_slug}.md")
        if not _MACRO_RE.match(meta["macro"]):
            raise AssetError(f"{path}: macro must match {_MACRO_RE.pattern}, got {meta['macro']!r}")
        schema = schema_for(kind)
        if len(json.dumps(schema).encode()) > SCHEMA_MAX_BYTES:
            raise AssetError(f"{path}: structured output schema exceeds {SCHEMA_MAX_BYTES} bytes")
        playbooks[kind] = PlaybookSpec(
            slug=kind.playbook_slug,
            kind=kind,
            upsert=PlaybookUpsert(
                title=meta["title"], body=body, macro=meta["macro"], structured_output_schema=schema
            ),
            path=path,
        )
    missing = [k.name for k in Kind if k not in playbooks]
    if missing:
        raise AssetError(f"{pb_dir}: no playbook for kinds {missing}")
    macros = [p.upsert.macro or "" for p in playbooks.values()]
    if len(set(macros)) != len(macros):
        raise AssetError(f"{pb_dir}: duplicate macros {sorted(macros)}")

    knowledge: list[KnowledgeSpec] = []
    kn_dir = root / KNOWLEDGE_DIR
    for path in sorted(kn_dir.glob("*.md")):
        meta, body = _front_matter(path)
        for key in ("name", "trigger"):
            if key not in meta:
                raise AssetError(f"{path}: front matter needs `{key}`")
        knowledge.append(
            KnowledgeSpec(
                slug=path.stem,
                upsert=NoteUpsert(
                    name=meta["name"],
                    body=body,
                    trigger=meta["trigger"],
                    pinned_repo=meta.get("pinned_repo") or None,
                ),
                path=path,
            )
        )
    if not knowledge:
        raise AssetError(f"{kn_dir}: at least one knowledge note is required")
    names = [k.upsert.name for k in knowledge]
    if len(set(names)) != len(names):
        raise AssetError(f"{kn_dir}: duplicate note names {sorted(names)}")
    return AssetBundle(playbooks=playbooks, knowledge=knowledge)


Action = Literal["created", "updated", "unchanged", "adopted", "would_create", "would_update"]


@dataclass(frozen=True)
class AssetAction:
    asset_kind: AssetKind
    slug: str
    action: Action
    remote_id: str | None
    reason: str = ""


@dataclass
class SyncReport:
    actions: list[AssetAction] = field(default_factory=list)
    dry_run: bool = False

    @property
    def writes(self) -> int:
        return sum(1 for a in self.actions if a.action in ("created", "updated"))

    @property
    def noop(self) -> bool:
        return all(a.action in ("unchanged", "adopted") for a in self.actions)

    def playbook_ids(self) -> dict[str, str]:
        return {
            a.slug: a.remote_id
            for a in self.actions
            if a.asset_kind == "playbook" and a.remote_id is not None
        }

    def knowledge_ids(self) -> list[str]:
        return [
            a.remote_id
            for a in self.actions
            if a.asset_kind == "knowledge" and a.remote_id is not None
        ]


class AssetSyncer:
    """Reconcile Devin with the committed bundle. Remote lookup order per asset: the id persisted
    in `devin_assets` if it still exists, else an exact title/name match (an asset created by hand
    or by a previous database is adopted, never duplicated), else create."""

    def __init__(self, devin: DevinClient, engine: Engine, bundle: AssetBundle) -> None:
        self.devin = devin
        self.engine = engine
        self.bundle = bundle

    def sync(self, *, dry_run: bool = False) -> SyncReport:
        report = SyncReport(dry_run=dry_run)
        remote_pbs = {p.playbook_id: p for p in self.devin.list_playbooks()}
        remote_notes = {n.note_id: n for n in self.devin.list_notes()}
        with session_scope(self.engine) as db:
            rows = {
                (r.asset_kind, r.slug): r
                for r in db.exec(select(DevinAsset).order_by(col(DevinAsset.id))).all()
            }
            for spec in self.bundle.playbooks.values():
                row = rows.get(("playbook", spec.slug))
                current = self._locate_playbook(row, spec, remote_pbs)
                action = self._reconcile_playbook(spec, current, dry_run)
                report.actions.append(action)
                if not dry_run and action.remote_id is not None:
                    self._persist(
                        db,
                        row,
                        "playbook",
                        spec.slug,
                        spec.upsert.title,
                        action,
                        spec.content_sha256,
                    )
            for kspec in self.bundle.knowledge:
                row = rows.get(("knowledge", kspec.slug))
                note = self._locate_note(row, kspec, remote_notes)
                action = self._reconcile_note(kspec, note, dry_run)
                report.actions.append(action)
                if not dry_run and action.remote_id is not None:
                    self._persist(
                        db,
                        row,
                        "knowledge",
                        kspec.slug,
                        kspec.upsert.name,
                        action,
                        kspec.content_sha256,
                    )
        return report

    @staticmethod
    def _locate_playbook(
        row: DevinAsset | None, spec: PlaybookSpec, remote: dict[str, PlaybookRecord]
    ) -> PlaybookRecord | None:
        if row is not None and row.remote_id in remote:
            return remote[row.remote_id]
        same_title = [p for p in remote.values() if p.title == spec.upsert.title]
        if len(same_title) > 1:
            raise AssetError(
                f"{len(same_title)} playbooks titled {spec.upsert.title!r} exist at Devin; "
                "delete the extras by hand before syncing"
            )
        return same_title[0] if same_title else None

    @staticmethod
    def _locate_note(
        row: DevinAsset | None, spec: KnowledgeSpec, remote: dict[str, NoteRecord]
    ) -> NoteRecord | None:
        if row is not None and row.remote_id in remote:
            return remote[row.remote_id]
        same_name = [n for n in remote.values() if n.name == spec.upsert.name]
        if len(same_name) > 1:
            raise AssetError(
                f"{len(same_name)} notes named {spec.upsert.name!r} exist at Devin; "
                "delete the extras by hand before syncing"
            )
        return same_name[0] if same_name else None

    def _reconcile_playbook(
        self, spec: PlaybookSpec, current: PlaybookRecord | None, dry_run: bool
    ) -> AssetAction:
        if current is None:
            if dry_run:
                return AssetAction("playbook", spec.slug, "would_create", None)
            rec = self.devin.create_playbook(spec.upsert)
            return AssetAction("playbook", spec.slug, "created", rec.playbook_id)
        if current.matches(spec.upsert):
            return AssetAction("playbook", spec.slug, "unchanged", current.playbook_id)
        if dry_run:
            return AssetAction("playbook", spec.slug, "would_update", current.playbook_id)
        rec = self.devin.update_playbook(current.playbook_id, spec.upsert)
        return AssetAction("playbook", spec.slug, "updated", rec.playbook_id)

    def _reconcile_note(
        self, spec: KnowledgeSpec, current: NoteRecord | None, dry_run: bool
    ) -> AssetAction:
        if current is None:
            if dry_run:
                return AssetAction("knowledge", spec.slug, "would_create", None)
            rec = self.devin.create_note(spec.upsert)
            return AssetAction("knowledge", spec.slug, "created", rec.note_id)
        if current.matches(spec.upsert):
            return AssetAction("knowledge", spec.slug, "unchanged", current.note_id)
        if dry_run:
            return AssetAction("knowledge", spec.slug, "would_update", current.note_id)
        rec = self.devin.update_note(current.note_id, spec.upsert)
        return AssetAction("knowledge", spec.slug, "updated", rec.note_id)

    @staticmethod
    def _persist(
        db: Session,
        row: DevinAsset | None,
        asset_kind: AssetKind,
        slug: str,
        title: str,
        action: AssetAction,
        content_sha256: str,
    ) -> None:
        assert action.remote_id is not None
        last = action.action
        if row is None:
            row = DevinAsset(
                asset_kind=asset_kind,
                slug=slug,
                remote_id=action.remote_id,
                title=title,
                content_sha256=content_sha256,
                last_action="adopted" if last == "unchanged" else last,
            )
        else:
            if row.remote_id != action.remote_id and last == "unchanged":
                last = "adopted"
            row.remote_id = action.remote_id
            row.title = title
            row.content_sha256 = content_sha256
            row.last_action = last
            row.synced_at = utcnow()
        db.add(row)
        # one asset per transaction: a later API failure must not lose an id Devin already confirmed
        db.commit()


@dataclass(frozen=True)
class PersistedAssets:
    playbook_ids: dict[Kind, str]
    knowledge_ids: list[str]
    drifted: list[str]
    missing: list[str]

    @property
    def ok(self) -> bool:
        return not self.drifted and not self.missing


def persisted_assets(engine: Engine, bundle: AssetBundle) -> PersistedAssets:
    """What the live orchestrator may use, checked against the committed tree without any network
    call: a playbook whose file changed since the last sync is `drifted`, one never synced is
    `missing`. Either makes the live run refuse to start until `assets sync` runs."""
    with session_scope(engine) as db:
        rows = {
            (r.asset_kind, r.slug): (r.remote_id, r.content_sha256)
            for r in db.exec(select(DevinAsset)).all()
        }
    playbook_ids: dict[Kind, str] = {}
    knowledge_ids: list[str] = []
    drifted: list[str] = []
    missing: list[str] = []
    for kind, spec in bundle.playbooks.items():
        found = rows.get(("playbook", spec.slug))
        if found is None:
            missing.append(f"playbook:{spec.slug}")
            continue
        remote_id, sha = found
        if sha != spec.content_sha256:
            drifted.append(f"playbook:{spec.slug}")
        playbook_ids[kind] = remote_id
    for kspec in bundle.knowledge:
        found = rows.get(("knowledge", kspec.slug))
        if found is None:
            missing.append(f"knowledge:{kspec.slug}")
            continue
        remote_id, sha = found
        if sha != kspec.content_sha256:
            drifted.append(f"knowledge:{kspec.slug}")
        knowledge_ids.append(remote_id)
    return PersistedAssets(playbook_ids, knowledge_ids, drifted, missing)


__all__ = [
    "AssetAction",
    "AssetBundle",
    "AssetError",
    "AssetSyncer",
    "KnowledgeSpec",
    "PersistedAssets",
    "PlaybookSpec",
    "SyncReport",
    "load_assets",
    "persisted_assets",
]
