from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG_PATH = ROOT / "catalog" / "tools.json"

class CatalogError(ValueError):
    pass

def load_catalog(path=CATALOG_PATH):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    tools = {t["id"]: t for t in data["tools"]}
    cats = {c["id"] for c in data["categories"]}
    if len(tools) != len(data["tools"]) or any(t["category"] not in cats for t in tools.values()):
        raise CatalogError("duplicate tool ID or unknown category")
    for t in tools.values():
        if t["recipe"] not in {"system", "python", "gem", "source", "pwndbg"}:
            raise CatalogError(f"invalid recipe: {t['id']}")
    return data, tools

def resolve(selection, tools=None):
    if tools is None: tools = load_catalog()[1]
    ordered, visiting, done = [], set(), set()
    def visit(item):
        if item not in tools: raise CatalogError(f"unknown tool: {item}")
        if item in visiting: raise CatalogError(f"dependency cycle: {item}")
        if item in done: return
        visiting.add(item)
        for dep in tools[item].get("depends_on", []): visit(dep)
        visiting.remove(item); done.add(item); ordered.append(item)
    for item in selection: visit(item)
    return ordered

def select_categories(categories, data=None, tools=None):
    data, tools = (data, tools) if data is not None else load_catalog()
    known = {c["id"] for c in data["categories"]}
    unknown = set(categories) - known
    if unknown: raise CatalogError("unknown category: " + ",".join(sorted(unknown)))
    return resolve([t["id"] for t in data["tools"] if t["category"] in categories], tools)
