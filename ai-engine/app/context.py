"""Extraction du code source autour d'une alerte, pour donner du contexte au LLM."""
import os


def find_source(sources: dict[str, str], path: str | None) -> str | None:
    if not path:
        return None
    if path in sources:
        return sources[path]
    for key, content in sources.items():
        if key.endswith("/" + path) or path.endswith("/" + key):
            return content
    base = os.path.basename(path)
    for key, content in sources.items():
        if os.path.basename(key) == base:
            return content
    return None


def code_context(sources: dict[str, str], path: str | None, line: int | None, radius: int = 5) -> str:
    content = find_source(sources, path)
    if content is None:
        return ""
    lines = content.splitlines()
    if not line:
        start, end = 0, min(len(lines), 40)
    else:
        start, end = max(line - 1 - radius, 0), min(line + radius, len(lines))
    return "\n".join(f"{i + 1:4d} | {lines[i]}" for i in range(start, end))


def application_overview(sources: dict[str, str], limit: int = 3000) -> str:
    """Résumé du code de l'application, pour juger si une bibliothèque vulnérable est utilisée."""
    parts, size = [], 0
    for key in sorted(sources):
        if not (key.endswith(".py") or key.endswith("requirements.txt")):
            continue
        block = f"### {key}\n{sources[key]}"
        if size + len(block) > limit:
            block = block[: max(limit - size, 0)]
        parts.append(block)
        size += len(block)
        if size >= limit:
            break
    return "\n\n".join(parts)
