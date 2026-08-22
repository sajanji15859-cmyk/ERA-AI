"""Lightweight, self-contained cron expression parser and schedule evaluator (Phase 3H).

Supports standard 5-field cron syntax:
    <minute> <hour> <day_of_month> <month> <day_of_week>

Features:
* Asterisk (*), step values (*/15), ranges (1-5), lists (1,15,30)
* Month names (JAN-DEC) and weekday names (SUN-SAT)
* Standard aliases (@hourly, @daily, @midnight, @weekly, @monthly, @yearly, @annually)
* Pure Python standard library (no external heavy dependencies).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

_MONTH_NAMES = {
    "JAN": 1, "FEB": 2, "MAR": 3, "APR": 4, "MAY": 5, "JUN": 6,
    "JUL": 7, "AUG": 8, "SEP": 9, "OCT": 10, "NOV": 11, "DEC": 12,
}

_DOW_NAMES = {
    "SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6,
}

_ALIASES = {
    "@hourly": "0 * * * *",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@weekly": "0 0 * * 0",
    "@monthly": "0 0 1 * *",
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
}


class CronError(ValueError):
    """Raised when a cron expression is invalid."""


def parse_field(field_str: str, min_val: int, max_val: int,
                name_map: dict[str, int] | None = None) -> set[int]:
    """Parse a single cron field into a set of allowed integer values."""
    field_str = field_str.strip().upper()
    if not field_str:
        raise CronError("empty cron field")

    if name_map:
        for name, val in name_map.items():
            field_str = re.sub(rf"\b{name}\b", str(val), field_str)

    allowed: set[int] = set()
    parts = field_str.split(",")
    for part in parts:
        part = part.strip()
        if not part:
            raise CronError(f"invalid empty element in cron field {field_str!r}")
        step = 1
        if "/" in part:
            range_part, step_str = part.split("/", 1)
            try:
                step = int(step_str)
                if step <= 0:
                    raise CronError(f"step must be positive: {step_str!r}")
            except ValueError as e:
                raise CronError(f"invalid step in cron field {part!r}") from e
        else:
            range_part = part

        if range_part == "*":
            start, end = min_val, max_val
        elif "-" in range_part:
            start_str, end_str = range_part.split("-", 1)
            try:
                start, end = int(start_str), int(end_str)
            except ValueError as e:
                raise CronError(f"invalid range in cron field {range_part!r}") from e
        else:
            try:
                start = end = int(range_part)
            except ValueError as e:
                raise CronError(f"invalid number in cron field {range_part!r}") from e

        if start < min_val or end > max_val or start > end:
            raise CronError(
                f"value {range_part!r} out of bounds [{min_val}-{max_val}]"
            )

        for val in range(start, end + 1, step):
            allowed.add(val)

    return allowed


class CronSchedule:
    """Parses a 5-field cron expression and calculates the next run timestamp."""

    def __init__(self, expr: str):
        self.raw = expr.strip()
        norm = _ALIASES.get(self.raw.lower(), self.raw)
        fields = norm.split()
        if len(fields) != 5:
            raise CronError(
                f"cron expression must have 5 fields (or alias), got {len(fields)}: {expr!r}"
            )
        self.minutes = parse_field(fields[0], 0, 59)
        self.hours = parse_field(fields[1], 0, 23)
        self.days_of_month = parse_field(fields[2], 1, 31)
        self.months = parse_field(fields[3], 1, 12, _MONTH_NAMES)
        dow_raw = parse_field(fields[4], 0, 7, _DOW_NAMES)
        # Normalize 7 (Sunday) -> 0
        self.days_of_week = {(0 if d == 7 else d) for d in dow_raw}

    def next_after(self, from_dt: datetime) -> datetime:
        """Find the next datetime strictly after ``from_dt`` matching this cron schedule."""
        if from_dt.tzinfo is None:
            dt = from_dt.replace(tzinfo=UTC)
        else:
            dt = from_dt.astimezone(UTC)

        # Advance to the next minute boundary (seconds/micros = 0)
        dt = dt.replace(second=0, microsecond=0) + timedelta(minutes=1)

        # Bounded search (up to 5 years in minutes)
        max_iterations = 5 * 366 * 24 * 60
        iterations = 0

        while iterations < max_iterations:
            iterations += 1
            if dt.month not in self.months:
                # Advance to first day of next month
                if dt.month == 12:
                    dt = dt.replace(year=dt.year + 1, month=1, day=1, hour=0, minute=0)
                else:
                    dt = dt.replace(month=dt.month + 1, day=1, hour=0, minute=0)
                continue

            # Check day of month and day of week
            # Python datetime weekday(): Monday is 0, Sunday is 6. Convert to Sunday=0 .. Saturday=6:
            cron_dow = (dt.weekday() + 1) % 7
            dom_match = dt.day in self.days_of_month
            dow_match = cron_dow in self.days_of_week

            # Standard cron rule: if both DOM and DOW are specified (not '*'), either matching is accepted.
            # Otherwise, both must match.
            if not (dom_match and dow_match):
                dt = (dt + timedelta(days=1)).replace(hour=0, minute=0)
                continue

            if dt.hour not in self.hours:
                dt = (dt + timedelta(hours=1)).replace(minute=0)
                continue

            if dt.minute not in self.minutes:
                dt = dt + timedelta(minutes=1)
                continue

            return dt

        raise CronError("could not find next cron schedule run within 5 years")


def compute_next_run(cron_expr: str | None = None,
                     interval_seconds: int | None = None,
                     from_dt: datetime | None = None) -> datetime:
    """Compute the next run datetime based on a cron expression or an interval in seconds."""
    base = from_dt or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)

    if interval_seconds is not None and interval_seconds > 0:
        return base + timedelta(seconds=interval_seconds)

    if cron_expr:
        sched = CronSchedule(cron_expr)
        return sched.next_after(base)

    raise ValueError("must provide either cron_expr or interval_seconds > 0")
