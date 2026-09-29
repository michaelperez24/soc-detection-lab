"""Transparent, deterministic rules for demonstration security events."""
from __future__ import annotations

import pandas as pd

REQUIRED = {"timestamp", "event_id", "source_ip", "target_user", "target_system", "event_type", "outcome"}


def load_events(source) -> pd.DataFrame:
    events = pd.read_csv(source, dtype=str)
    missing = REQUIRED - set(events.columns)
    if missing:
        raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")
    if events.empty:
        raise ValueError("The event file is empty")
    if events[list(REQUIRED)].isna().any().any():
        raise ValueError("Required event fields cannot be blank")
    if events.event_id.duplicated().any():
        raise ValueError("Event IDs must be unique")
    events["timestamp"] = pd.to_datetime(events.timestamp, utc=True, errors="coerce")
    if events.timestamp.isna().any():
        raise ValueError("All timestamps must be valid ISO dates")
    return events.sort_values("timestamp").reset_index(drop=True)


def detect(events: pd.DataFrame, threshold: int = 5, window_minutes: int = 10) -> pd.DataFrame:
    """Find failure bursts per IP/user, success after burst, and reported phishing/malware."""
    alerts = []
    failures = events[(events.event_type == "login") & (events.outcome == "failure")]
    for (ip, user), group in failures.groupby(["source_ip", "target_user"]):
        group = group.sort_values("timestamp")
        for idx in range(len(group)):
            end = group.iloc[idx].timestamp
            window = group[(group.timestamp > end - pd.Timedelta(minutes=window_minutes)) & (group.timestamp <= end)]
            if len(window) < threshold:
                continue
            # One alert per contiguous burst; no alert for every additional failure.
            if any(a["source_ip"] == ip and a["target_user"] == user and a["rule"] == "Failed login burst" and end - a["timestamp"] <= pd.Timedelta(minutes=window_minutes) for a in alerts):
                continue
            alerts.append(_alert(end, "Failed login burst", "High", ip, user, group.iloc[idx].target_system, ", ".join(window.event_id)))
    for burst in list(alerts):
        successes = events[(events.event_type == "login") & (events.outcome == "success") & (events.source_ip == burst["source_ip"]) & (events.target_user == burst["target_user"]) & (events.timestamp > burst["timestamp"]) & (events.timestamp <= burst["timestamp"] + pd.Timedelta(minutes=window_minutes))]
        if not successes.empty:
            success = successes.iloc[0]
            alerts.append(_alert(success.timestamp, "Successful login after failures", "Critical", success.source_ip, success.target_user, success.target_system, success.event_id))
    for _, event in events.iterrows():
        if event.event_type == "phishing" and event.outcome == "reported":
            alerts.append(_alert(event.timestamp, "Reported phishing", "Medium", event.source_ip, event.target_user, event.target_system, event.event_id))
        elif event.event_type == "malware" and event.outcome == "blocked":
            alerts.append(_alert(event.timestamp, "Blocked malware", "Medium", event.source_ip, event.target_user, event.target_system, event.event_id))
    columns = ["timestamp", "rule", "severity", "source_ip", "target_user", "target_system", "event_ids", "status"]
    return pd.DataFrame(alerts, columns=columns).sort_values("timestamp", ascending=False).reset_index(drop=True)


def _alert(timestamp, rule, severity, ip, user, system, ids):
    return dict(timestamp=timestamp, rule=rule, severity=severity, source_ip=ip, target_user=user, target_system=system, event_ids=ids, status="New")
