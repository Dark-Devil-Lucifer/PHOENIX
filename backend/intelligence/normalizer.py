import hashlib
import ipaddress
from urllib.parse import urlsplit


SUPPORTED_TYPES = {
    "ip",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
}


def normalize_indicator(
    indicator_type: str,
    value: str,
) -> str:

    indicator_type = indicator_type.lower().strip()
    value = value.strip()

    if indicator_type not in SUPPORTED_TYPES:
        raise ValueError(
            f"Unsupported indicator type: {indicator_type}"
        )

    if not value:
        raise ValueError("Indicator value cannot be empty")

    if indicator_type == "ip":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError(
                f"Invalid IP address: {value}"
            ) from exc

    if indicator_type == "domain":
        value = value.lower().rstrip(".")

        if value.startswith("*."):
            value = value[2:]

        return value

    if indicator_type == "url":
        parsed = urlsplit(value)

        if not parsed.scheme or not parsed.netloc:
            raise ValueError(
                f"Invalid URL: {value}"
            )

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        if not hostname:
            raise ValueError(
                f"Invalid URL hostname: {value}"
            )

        port = parsed.port

        if port:
            return f"{scheme}://{hostname}:{port}{parsed.path}"
        
        return f"{scheme}://{hostname}{parsed.path}"

    if indicator_type in {"md5", "sha1", "sha256"}:
        normalized = value.lower()

        expected_lengths = {
            "md5": 32,
            "sha1": 40,
            "sha256": 64,
        }

        if len(normalized) != expected_lengths[indicator_type]:
            raise ValueError(
                f"Invalid {indicator_type} hash length"
            )

        try:
            int(normalized, 16)
        except ValueError as exc:
            raise ValueError(
                f"Invalid {indicator_type} hash"
            ) from exc

        return normalized

    return value


def indicator_uid(
    indicator_type: str,
    normalized_value: str,
) -> str:

    digest = hashlib.sha256(
        f"{indicator_type}:{normalized_value}".encode()
    ).hexdigest()[:24]

    return f"IOC-{digest.upper()}"
