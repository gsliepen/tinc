"""Some hardcoded constants."""

from .proc import Feature, Tinc

# True if tincd has sandbox support
HAVE_SANDBOX = Feature.SANDBOX in Tinc().features

# Maximum supported sandbox level
SANDBOX_LEVEL = "high" if Feature.SANDBOX in Tinc().features else "off"
