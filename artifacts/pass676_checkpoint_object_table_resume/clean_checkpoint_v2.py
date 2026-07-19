#!/usr/bin/env python3
"""Versioned, immutable checkpoints for the established clean Unicorn replay.

The format deliberately contains no pickle data or host handles.  A raw Unicorn
context payload is tied to the exact Unicorn version/context size, while a
portable explicit register inventory provides independent validation.
"""
from __future__ import annotations

import collections
import ctypes
import hashlib
import json
import os
import platform
from pathlib import Path
from typing import Any

import unicorn
import unicorn.x86_const as x86

SCHEMA_VERSION = "aion-clean-checkpoint/v2"
MEMORY_PAYLOAD = "mapped_memory.bin"
CONTEXT_PAYLOAD = "unicorn_context.bin"
OBJECT_PAYLOAD = "synthetic_objects.bin"
MANIFEST = "checkpoint_manifest.json"


class CheckpointError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"kind": "bytes", "hex": value.hex()}
    if isinstance(value, tuple):
        return {"kind": "tuple", "items": [_json_value(x) for x in value]}
    if isinstance(value, list):
        return [_json_value(x) for x in value]
    if isinstance(value, set):
        return {"kind": "set", "items": sorted((_json_value(x) for x in value), key=lambda x: json.dumps(x, sort_keys=True))}
    if isinstance(value, collections.Counter):
        return {"kind": "counter", "items": [[_json_value(k), int(v)] for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))]}
    if isinstance(value, dict):
        return {"kind": "dict", "items": [[_json_value(k), _json_value(v)] for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))]}
    raise CheckpointError(f"nonportable state value rejected: {type(value).__name__}")


def _from_json_value(value: Any) -> Any:
    if not isinstance(value, dict) or "kind" not in value:
        if isinstance(value, list):
            return [_from_json_value(x) for x in value]
        return value
    kind = value["kind"]
    if kind == "bytes":
        return bytes.fromhex(value["hex"])
    if kind == "tuple":
        return tuple(_from_json_value(x) for x in value["items"])
    if kind == "set":
        return set(_from_json_value(x) for x in value["items"])
    if kind == "counter":
        return collections.Counter({_from_json_value(k): int(v) for k, v in value["items"]})
    if kind == "dict":
        return {_from_json_value(k): _from_json_value(v) for k, v in value["items"]}
    raise CheckpointError(f"unknown encoded value kind: {kind}")


def explicit_registers(uc: unicorn.Uc) -> dict[str, Any]:
    """Read every register constant supported by this Unicorn x86 build."""
    out: dict[str, Any] = {}
    seen: set[int] = set()
    for name in sorted(n for n in dir(x86) if n.startswith("UC_X86_REG_") and n != "UC_X86_REG_INVALID"):
        reg_id = getattr(x86, name)
        if not isinstance(reg_id, int) or reg_id in seen:
            continue
        try:
            value = uc.reg_read(reg_id)
        except Exception:
            continue
        seen.add(reg_id)
        out[name] = _json_value(value)
    required = {"UC_X86_REG_RIP", "UC_X86_REG_RSP", "UC_X86_REG_RFLAGS", "UC_X86_REG_RAX", "UC_X86_REG_XMM0"}
    missing = sorted(required - set(out))
    if missing:
        raise CheckpointError(f"required register reads failed: {missing}")
    return out


def restore_explicit_registers(uc: unicorn.Uc, registers: dict[str, Any]) -> None:
    for name, encoded in registers.items():
        if not hasattr(x86, name):
            raise CheckpointError(f"register unavailable in current Unicorn: {name}")
        try:
            uc.reg_write(getattr(x86, name), _from_json_value(encoded))
        except Exception as exc:
            raise CheckpointError(f"cannot restore register {name}: {exc}") from exc


STATE_FIELDS = (
    "insn", "stop", "last_rip", "maxinsn", "rflags", "reason", "start_mode",
    "api_by_addr", "api_calls", "next_api", "fake_modules", "fake_module_next", "import_names",
    "next_heap", "heap_end", "next_handle", "mapped_pages", "dynamic_maps",
    "image_writes", "image_write_ranges", "executed_pages", "hot", "invalid_insn",
    "first_zero_text_write", "zero_regions", "stack_base", "stack_size", "stack_top",
    "api_base", "api_size", "sentinel", "teb", "peb", "hotloop_calls", "hotloop_bytes",
    "hotloop_max", "rep_calls", "rep_bytes", "target_page_events", "materialized",
    "forbidden_unmapped", "total_instructions", "mapping_protection_events",
)


def _serialize_state(em: Any, object_blob: bytearray) -> dict[str, Any]:
    """Serialize Python state and the complete synthetic-object graph.

    Windows file-mapping objects remain valid after their source file handle is
    closed.  The emulator models this by retaining the same Python object in
    ``mapping_handles`` after removing its entry from ``file_handles``.  A
    handle-to-handle representation therefore loses valid mapping-owned
    objects.  Version 2 assigns deterministic object IDs to every distinct
    object reachable from either handle table and records each table as an
    object reference.
    """
    state: dict[str, Any] = {}
    missing = []
    for name in STATE_FIELDS:
        if hasattr(em, name):
            state[name] = _json_value(getattr(em, name))
        else:
            missing.append(name)
    state["__absent_fields__"] = missing

    references: list[tuple[str, int, Any]] = []
    for guest_handle, obj in sorted(em.file_handles.items()):
        references.append(("file", int(guest_handle), obj))
    for guest_handle, obj in sorted(em.mapping_handles.items()):
        references.append(("mapping", int(guest_handle), obj))

    object_ids: dict[int, str] = {}
    objects: list[dict[str, Any]] = []
    files: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []

    for table, guest_handle, obj in references:
        if not isinstance(obj, dict):
            raise CheckpointError(
                f"synthetic handle {guest_handle:#x} references unsupported object type {type(obj).__name__}"
            )
        identity = id(obj)
        object_id = object_ids.get(identity)
        if object_id is None:
            if "data" not in obj:
                raise CheckpointError(f"synthetic object for handle {guest_handle:#x} has no data payload")
            try:
                data = bytes(obj["data"])
            except Exception as exc:
                raise CheckpointError(f"invalid synthetic object data for handle {guest_handle:#x}: {exc}") from exc
            metadata = {key: value for key, value in obj.items() if key != "data"}
            object_id = f"object_{len(objects):06d}"
            object_ids[identity] = object_id
            offset = len(object_blob)
            object_blob.extend(data)
            objects.append({
                "object_id": object_id,
                "metadata": _json_value(metadata),
                "payload_offset": offset,
                "payload_size": len(data),
                "payload_sha256": sha256_bytes(data),
            })
        record = {"guest_handle": guest_handle, "object_id": object_id}
        (files if table == "file" else mappings).append(record)

    return {
        "fields": state,
        "synthetic_objects": objects,
        "file_handles": files,
        "mapping_handles": mappings,
    }


def _validate_python_state(encoded: dict[str, Any], object_data: bytes) -> None:
    if not isinstance(encoded, dict):
        raise CheckpointError("checkpoint python_state is not an object")
    required = {"fields", "synthetic_objects", "file_handles", "mapping_handles"}
    if not required.issubset(encoded):
        raise CheckpointError(f"checkpoint python_state is incomplete: missing {sorted(required - set(encoded))}")
    if not isinstance(encoded["fields"], dict):
        raise CheckpointError("checkpoint python_state fields are invalid")

    object_ids: set[str] = set()
    last_end = 0
    for item in encoded["synthetic_objects"]:
        if not isinstance(item, dict):
            raise CheckpointError(f"invalid synthetic object record: {item!r}")
        object_id = item.get("object_id")
        offset = item.get("payload_offset")
        size = item.get("payload_size")
        digest = item.get("payload_sha256")
        if not isinstance(object_id, str) or not object_id or object_id in object_ids:
            raise CheckpointError(f"duplicate or invalid synthetic object id: {object_id!r}")
        if not isinstance(offset, int) or not isinstance(size, int) or offset != last_end or size < 0:
            raise CheckpointError(f"conflicting synthetic object payload range: {item}")
        end = offset + size
        if end > len(object_data):
            raise CheckpointError(f"incomplete synthetic object payload: {object_id}")
        data = object_data[offset:end]
        if not isinstance(digest, str) or sha256_bytes(data) != digest:
            raise CheckpointError(f"synthetic object payload mismatch: {object_id}")
        metadata = _from_json_value(item.get("metadata"))
        if not isinstance(metadata, dict) or "data" in metadata:
            raise CheckpointError(f"invalid synthetic object metadata: {object_id}")
        object_ids.add(object_id)
        last_end = end
    if last_end != len(object_data):
        raise CheckpointError("synthetic-object payload has unclaimed bytes")

    for table_name in ("file_handles", "mapping_handles"):
        records = encoded[table_name]
        if not isinstance(records, list):
            raise CheckpointError(f"{table_name} is not a list")
        seen_handles: set[int] = set()
        for item in records:
            if not isinstance(item, dict):
                raise CheckpointError(f"invalid {table_name} record: {item!r}")
            guest_handle = item.get("guest_handle")
            object_id = item.get("object_id")
            if not isinstance(guest_handle, int) or guest_handle < 0 or guest_handle in seen_handles:
                raise CheckpointError(f"duplicate or invalid {table_name} handle: {guest_handle!r}")
            if object_id not in object_ids:
                raise CheckpointError(f"{table_name}[{guest_handle:#x}] references absent object {object_id!r}")
            seen_handles.add(guest_handle)


def _restore_state(em: Any, encoded: dict[str, Any], object_data: bytes) -> None:
    _validate_python_state(encoded, object_data)
    fields = dict(encoded["fields"])
    absent = set(fields.pop("__absent_fields__", []))
    for name, value in fields.items():
        if name in {"stop"}:
            continue
        restored = _from_json_value(value)
        if name == "import_names":
            restored = collections.defaultdict(list, restored)
        setattr(em, name, restored)
    for name in absent:
        if hasattr(em, name):
            delattr(em, name)

    objects: dict[str, dict[str, Any]] = {}
    for item in encoded["synthetic_objects"]:
        start = item["payload_offset"]
        end = start + item["payload_size"]
        metadata = _from_json_value(item["metadata"])
        obj = dict(metadata)
        obj["data"] = object_data[start:end]
        objects[item["object_id"]] = obj

    em.file_handles = {
        item["guest_handle"]: objects[item["object_id"]]
        for item in encoded["file_handles"]
    }
    em.mapping_handles = {
        item["guest_handle"]: objects[item["object_id"]]
        for item in encoded["mapping_handles"]
    }
    em.stop = ""

def _context_bytes(uc: unicorn.Uc) -> tuple[bytes, int]:
    context = uc.context_save()
    size = int(context.size)
    return ctypes.string_at(context._context, size), size


def _restore_context(uc: unicorn.Uc, raw: bytes, expected_size: int) -> None:
    context = uc.context_save()
    if int(context.size) != expected_size or len(raw) != expected_size:
        raise CheckpointError(f"Unicorn context size mismatch: checkpoint={expected_size}, current={context.size}")
    ctypes.memmove(context._context, raw, len(raw))
    uc.context_restore(context)


def save_checkpoint(em: Any, directory: Path, identity: dict[str, Any], hook_config: dict[str, Any]) -> Path:
    directory = Path(directory).resolve()
    if directory.exists() and any(directory.iterdir()):
        raise CheckpointError(f"refusing to overwrite nonempty checkpoint: {directory}")
    directory.mkdir(parents=True, exist_ok=True)

    memory_blob = bytearray()
    regions = []
    for begin, end, perms in sorted(em.uc.mem_regions()):
        size = int(end - begin + 1)
        data = bytes(em.uc.mem_read(begin, size))
        offset = len(memory_blob)
        memory_blob.extend(data)
        regions.append({"base": int(begin), "size": size, "permissions": int(perms),
                        "payload_offset": offset, "sha256": sha256_bytes(data)})
    if not regions:
        raise CheckpointError("checkpoint has no mapped regions")

    context_raw, context_size = _context_bytes(em.uc)
    object_blob = bytearray()
    python_state = _serialize_state(em, object_blob)
    payload_data = {
        MEMORY_PAYLOAD: bytes(memory_blob), CONTEXT_PAYLOAD: context_raw,
        OBJECT_PAYLOAD: bytes(object_blob),
    }
    for name, data in payload_data.items():
        (directory / name).write_bytes(data)

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "engine": {"name": "unicorn", "version": unicorn.__version__, "arch": "x86", "mode": "64",
                   "context_size": context_size, "python": platform.python_version(), "platform": platform.platform()},
        "identity": identity,
        "hook_configuration": hook_config,
        "registers": explicit_registers(em.uc),
        "regions": regions,
        "python_state": python_state,
        "payloads": {name: {"size": len(data), "sha256": sha256_bytes(data)} for name, data in payload_data.items()},
        "immutability": {"overwrite_permitted": False, "host_pid_serialized": False, "live_handles_serialized": False,
                         "python_pickle_serialized": False},
    }
    (directory / MANIFEST).write_bytes(canonical_json(manifest))
    return directory / MANIFEST


def validate_manifest(directory: Path, expected_identity: dict[str, Any] | None = None,
                      expected_hook_config: dict[str, Any] | None = None) -> tuple[dict[str, Any], dict[str, bytes]]:
    directory = Path(directory).resolve()
    path = directory / MANIFEST
    if not path.is_file():
        raise CheckpointError(f"missing checkpoint manifest: {path}")
    try:
        manifest = json.loads(path.read_text(encoding="ascii"))
    except Exception as exc:
        raise CheckpointError(f"invalid checkpoint manifest: {exc}") from exc
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise CheckpointError(f"unsupported schema version: {manifest.get('schema_version')!r}")
    engine = manifest.get("engine", {})
    if engine.get("name") != "unicorn" or engine.get("version") != unicorn.__version__ or engine.get("arch") != "x86" or engine.get("mode") != "64":
        raise CheckpointError(f"checkpoint engine identity mismatch: {engine}")
    if expected_identity is not None and manifest.get("identity") != expected_identity:
        raise CheckpointError("checkpoint replay-script/input/configuration identity mismatch")
    if expected_hook_config is not None and manifest.get("hook_configuration") != expected_hook_config:
        raise CheckpointError("checkpoint hook configuration mismatch")
    payloads: dict[str, bytes] = {}
    expected_names = {MEMORY_PAYLOAD, CONTEXT_PAYLOAD, OBJECT_PAYLOAD}
    if set(manifest.get("payloads", {})) != expected_names:
        raise CheckpointError("checkpoint payload inventory is incomplete or conflicting")
    for name in sorted(expected_names):
        p = directory / name
        if not p.is_file():
            raise CheckpointError(f"missing checkpoint payload: {name}")
        data = p.read_bytes()
        record = manifest["payloads"][name]
        if len(data) != record.get("size") or sha256_bytes(data) != record.get("sha256"):
            raise CheckpointError(f"checkpoint payload hash/size mismatch: {name}")
        payloads[name] = data
    _validate_python_state(manifest.get("python_state"), payloads[OBJECT_PAYLOAD])
    memory = payloads[MEMORY_PAYLOAD]
    last_end = 0
    intervals = []
    for region in manifest.get("regions", []):
        base, size, perms, offset = (region.get(k) for k in ("base", "size", "permissions", "payload_offset"))
        if not all(isinstance(x, int) for x in (base, size, perms, offset)) or base % 0x1000 or size <= 0 or size % 0x1000 or perms < 0 or perms > 7:
            raise CheckpointError(f"invalid mapped-region record: {region}")
        if offset != last_end or offset + size > len(memory):
            raise CheckpointError(f"conflicting/incomplete mapped-region payload: {region}")
        data = memory[offset:offset + size]
        if sha256_bytes(data) != region.get("sha256"):
            raise CheckpointError(f"mapped-region hash mismatch at {base:#x}")
        intervals.append((base, base + size))
        last_end = offset + size
    if last_end != len(memory) or not intervals:
        raise CheckpointError("mapped-memory payload has unclaimed bytes or no regions")
    for (_, prev_end), (next_base, _) in zip(sorted(intervals), sorted(intervals)[1:]):
        if next_base < prev_end:
            raise CheckpointError("overlapping mapped regions in checkpoint")
    return manifest, payloads


def load_checkpoint(em: Any, directory: Path, expected_identity: dict[str, Any], hook_config: dict[str, Any]) -> dict[str, Any]:
    manifest, payloads = validate_manifest(directory, expected_identity, hook_config)
    # Constructor-created mappings are setup state, not authoritative checkpoint
    # state.  Replace them in full; hooks remain attached to the Unicorn engine.
    for begin, end, _ in list(em.uc.mem_regions()):
        em.uc.mem_unmap(begin, end - begin + 1)
    memory = payloads[MEMORY_PAYLOAD]
    for region in manifest["regions"]:
        base, size, perms, offset = region["base"], region["size"], region["permissions"], region["payload_offset"]
        em.uc.mem_map(base, size, unicorn.UC_PROT_ALL)
        em.uc.mem_write(base, memory[offset:offset + size])
        em.uc.mem_protect(base, size, perms)
    _restore_state(em, manifest["python_state"], payloads[OBJECT_PAYLOAD])
    _restore_context(em.uc, payloads[CONTEXT_PAYLOAD], manifest["engine"]["context_size"])
    # Independent check catches context corruption or an incompatible native ABI.
    if explicit_registers(em.uc) != manifest["registers"]:
        raise CheckpointError("restored Unicorn context fails explicit-register validation")
    return manifest


def state_digest(em: Any, stop_reason: str) -> dict[str, Any]:
    regions = []
    page_hashes = []
    for begin, end, perms in sorted(em.uc.mem_regions()):
        data = bytes(em.uc.mem_read(begin, end - begin + 1))
        regions.append({"base": begin, "size": len(data), "permissions": perms, "sha256": sha256_bytes(data)})
        for offset in range(0, len(data), 0x1000):
            page = data[offset:offset + 0x1000]
            page_hashes.append({"va": begin + offset, "size": len(page), "sha256": sha256_bytes(page)})
    object_blob = bytearray()
    state = _serialize_state(em, object_blob)
    # Stop is supplied explicitly so checkpoint-boundary clearing is documented.
    state["fields"]["stop"] = _json_value(stop_reason)
    return {"rip": em.uc.reg_read(x86.UC_X86_REG_RIP), "registers": explicit_registers(em.uc),
            "regions": regions, "page_hashes": page_hashes, "state": state,
            "synthetic_object_payload_sha256": sha256_bytes(bytes(object_blob)), "stop_reason": stop_reason}


def hash_identity(paths: dict[str, Path], config: dict[str, Any]) -> dict[str, Any]:
    return {"files": {role: {"path": str(Path(path).resolve()), "size": Path(path).stat().st_size,
                              "sha256": sha256_file(Path(path))} for role, path in sorted(paths.items())},
            "deterministic_configuration": config}


def make_files_readonly(directory: Path) -> None:
    for p in Path(directory).iterdir():
        if p.is_file():
            os.chmod(p, 0o444)
