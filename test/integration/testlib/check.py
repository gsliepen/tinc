"""Simple assertions which print the expected and received values on failure."""

import typing as T

from .log import log

Val = T.TypeVar("Val")
Num = T.TypeVar("Num", int, float)


def false(value: T.Any) -> None:
    """Check that value is falsy."""
    if value:
        raise ValueError(f'expected "{value}" to be falsy')


def true(value: T.Any) -> None:
    """Check that value is truthy."""
    if not value:
        raise ValueError(f'expected "{value}" to be truthy', value)


def port(value: int) -> None:
    """Check that value resembles a port."""
    if not isinstance(value, int) or value < 1 or value > 65535:
        raise ValueError(f'expected "{value}" to be be a port')


def equals(expected: Val, actual: Val) -> None:
    """Check that the two values are equal."""
    if expected != actual:
        raise ValueError(f'expected "{expected}", got "{actual}"')


def has_prefix(text: T.AnyStr, prefix: T.AnyStr) -> None:
    """Check that text has prefix."""
    if not text.startswith(prefix):
        raise ValueError(f"expected {text!r} to start with {prefix!r}")


def greater(value: Num, than: Num) -> None:
    """Check that value is greater than the other value."""
    if value <= than:
        raise ValueError(f"value {value} must be greater than {than}")


def in_range(value: Num, gte: Num, lte: Num) -> None:
    """Check that value lies in the range [min, max]."""
    if not gte >= value >= lte:
        raise ValueError(f"value {value} must be between {gte} and {lte}")


def is_in(needle: Val, *haystacks: T.Container[Val]) -> None:
    """Check that at least one haystack includes needle."""
    for haystack in haystacks:
        if needle in haystack:
            return
    raise ValueError(f'expected any of "{haystacks}" to include "{needle}"')


def not_in(needle: Val, *haystacks: T.Container[Val]) -> None:
    """Check that all haystacks do not include needle."""
    for haystack in haystacks:
        if needle in haystack:
            raise ValueError(f'expected all "{haystacks}" NOT to include "{needle}"')


def nodes(node, want_nodes: int) -> None:
    """Check that node can reach exactly N nodes (including itself)."""
    log.debug("want %d reachable nodes from tinc %s", want_nodes, node)
    stdout, _ = node.cmd("dump", "reachable", "nodes")
    equals(want_nodes, len(stdout.splitlines()))


def files_eq(path0: str, path1: str) -> None:
    """Compare file contents, ignoring whitespace at both ends."""
    log.debug("comparing files %s and %s", path0, path1)

    def read(path: str) -> str:
        log.debug("reading file %s", path)
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()

    content0 = read(path0)
    content1 = read(path1)

    if content0 != content1:
        raise ValueError(f"expected files {path0} and {path1} to match")
