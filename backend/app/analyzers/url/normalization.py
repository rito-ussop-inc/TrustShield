"""URL normalization — safe, deterministic, fully documented (TRD §17, PRD §7 FR-2)."""
from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit


@dataclass
class NormalizationDetails:
    raw_url: str
    normalized_url: str
    scheme_inferred: bool = False
    original_scheme: str = ""
    effective_scheme: str = ""
    original_host: str = ""
    effective_host: str = ""
    original_port: int | None = None
    effective_port: int | None = None
    original_userinfo: str | None = None
    original_fragment: str = ""
    has_trailing_dot: bool = False
    warnings: list[str] = field(default_factory=list)
    transformations: list[str] = field(default_factory=list)


def normalize_url_details(raw: str) -> NormalizationDetails:
    raw_input = raw or ""
    trimmed = raw_input.strip()
    transformations: list[str] = []
    warnings: list[str] = []

    if trimmed != raw_input:
        transformations.append("Stripped leading/trailing whitespace")

    if not trimmed:
        return NormalizationDetails(
            raw_url=raw_input,
            normalized_url="",
            warnings=["URL string is empty"],
        )

    scheme_inferred = False
    if "://" not in trimmed:
        effective_url = "https://" + trimmed
        scheme_inferred = True
        transformations.append("Inferred missing scheme as https://")
        warnings.append("Scheme was missing from input; inferred https://")
    else:
        effective_url = trimmed

    try:
        parts = urlsplit(effective_url)
    except Exception as e:
        warnings.append(f"Failed to split URL components: {e}")
        return NormalizationDetails(
            raw_url=raw_input,
            normalized_url=trimmed,
            warnings=warnings,
        )

    original_scheme = parts.scheme
    effective_scheme = (parts.scheme or "https").lower()
    if effective_scheme != original_scheme and not scheme_inferred:
        transformations.append(f"Lowercased scheme '{original_scheme}' -> '{effective_scheme}'")

    raw_netloc = parts.netloc or ""
    userinfo: str | None = None
    if "@" in raw_netloc:
        userinfo_part = raw_netloc.split("@")[0]
        userinfo = userinfo_part
        warnings.append("URL authority contains userinfo credentials/handle")
        transformations.append("Extracted userinfo from authority for safe provider querying")

    orig_host = parts.hostname or ""
    host = orig_host.lower()
    if host != orig_host:
        transformations.append(f"Lowercased hostname '{orig_host}' -> '{host}'")

    has_trailing_dot = host.endswith(".")
    if has_trailing_dot:
        host = host.rstrip(".")
        warnings.append("Hostname contained trailing dot (DNS root zone indicator)")
        transformations.append("Removed trailing dot from canonical hostname")

    # IDNA punycode handling
    if host:
        try:
            ascii_host = host.encode("idna").decode("ascii")
            if ascii_host != host:
                transformations.append(f"Converted Unicode hostname '{host}' to IDNA punycode '{ascii_host}'")
                host = ascii_host
        except Exception as e:
            warnings.append(f"IDNA normalization warning: {e}")

    # Port handling: preserve explicit non-default ports
    original_port: int | None = None
    try:
        original_port = parts.port
    except ValueError:
        warnings.append("Invalid port value in URL")

    default_port = 80 if effective_scheme == "http" else 443 if effective_scheme == "https" else None
    include_port = original_port is not None and original_port != default_port

    if original_port is not None and original_port == default_port:
        transformations.append(f"Omitted redundant default port {original_port} from canonical authority")
    elif include_port:
        transformations.append(f"Preserved explicit non-default port {original_port}")

    # Reconstruct netloc without userinfo
    if "[" in raw_netloc and "]" in raw_netloc:
        # IPv6
        clean_ip6 = host.strip("[]")
        netloc = f"[{clean_ip6}]"
    else:
        netloc = host

    if include_port:
        netloc = f"{netloc}:{original_port}"

    # Path handling: preserve encoding, default empty path to '/'
    path = parts.path
    if not path:
        path = "/"
        transformations.append("Defaulted empty path to '/'")

    # Query handling: preserve exact query string
    query = parts.query or ""

    # Fragment handling: retain in metadata, omit from network canonical URL
    original_fragment = parts.fragment or ""
    if original_fragment:
        transformations.append(f"Stripped fragment '#{original_fragment}' from network target")
        warnings.append("URL contains fragment component (#); excluded from network request target")

    normalized = urlunsplit((effective_scheme, netloc, path, query, ""))

    return NormalizationDetails(
        raw_url=raw_input,
        normalized_url=normalized,
        scheme_inferred=scheme_inferred,
        original_scheme=original_scheme,
        effective_scheme=effective_scheme,
        original_host=orig_host,
        effective_host=host,
        original_port=original_port,
        effective_port=original_port if include_port else default_port,
        original_userinfo=userinfo,
        original_fragment=original_fragment,
        has_trailing_dot=has_trailing_dot,
        warnings=warnings,
        transformations=transformations,
    )


def normalize_url(raw: str) -> str:
    """Returns normalized URL string (backward compatible with existing callers)."""
    return normalize_url_details(raw).normalized_url
