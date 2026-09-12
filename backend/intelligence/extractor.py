import ipaddress


def extract_indicators_from_event(event) -> list[dict]:
    """
    Extract supported IOC candidates from a normalized
    SecurityEvent.

    Currently extracts source and destination IP addresses.
    """

    candidates = []

    values = [
        ("source_ip", event.source_ip),
        ("destination_ip", event.destination_ip),
    ]

    for field_name, value in values:
        if not value:
            continue

        try:
            normalized = str(
                ipaddress.ip_address(value.strip())
            )
        except ValueError:
            continue

        candidates.append(
            {
                "indicator_type": "ip",
                "value": value.strip(),
                "normalized_value": normalized,
                "field": field_name,
            }
        )

    return candidates
