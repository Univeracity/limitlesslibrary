"""Receiver code that deliberately imports the installed exact component."""

from _vendor import greeting


def render(name: str) -> str:
    return greeting.greeting(name)
