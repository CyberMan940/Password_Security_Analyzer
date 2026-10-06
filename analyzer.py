""" 
This module does not store, print, or transmit passwords.
"""
from __future__ import annotations

import math
import re
import string
from dataclasses import asdict, dataclass

COMMON_PASSWORDS = {
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "111111",
    "1234567",
    "sunshine",
    "qwerty",
    "iloveyou",
}

SEQUENTIAL_PATTERNS = {
    "123456",
    "abcdef",
    "qwerty",
    "asdfgh",
    "zxcvbn",
}

@dataclass(frozen=True)
class AnalysisResult:
    score: int
    label: str
    length: int
    entropy_bits: float
    warnings: list[str]
    suggestions: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _contains_sequence(password: str) -> bool:
    lowered = password.lower()
    for sequence in SEQUENTIAL_PATTERNS:
        if sequence in lowered or sequence[::-1] in lowered:
            return True
    for index in range(len(lowered) - 2):
        fragment = lowered[index : index + 3]
        if fragment in SEQUENTIAL_PATTERNS or fragment[::-1] in SEQUENTIAL_PATTERNS:
            return True
    return False


def _character_pool_size(password: str) -> int:
    pool = 0
    if any(char.islower() for char in password):
        pool += 26
    if any(char.isupper() for char in password):
        pool += 26
    if any(char.isdigit() for char in password):
        pool += 10
    if any(char in string.punctuation for char in password):
        pool += len(string.punctuation)
    return pool


def analyze_password(password: str) -> AnalysisResult:
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    length = len(password)
    lowered = password.lower()
    warnings: list[str] = []
    suggestions: list[str] = []

    if not password:
        return AnalysisResult(0, "very weak", 0, 0.0, ["Enter a password to analyze"], [])

    if lowered in COMMON_PASSWORDS:
        warnings.append("This is a commonly used password.")
    if length < 12:
        warnings.append("Password is shorter than 12 characters.")
        suggestions.append("Use at least 12 characters; 16 or more is better.")
    if len(set(password)) <= max(2, length // 3):
        warnings.append("This password repeats a small set of characters.")
    if _contains_sequence(password):
        warnings.append("This password contains a predictable sequence.")
        suggestions.append("Avoid keyboard patterns and alphabet or number sequences.")
    if re.search(r"(.)\1\1", password):
        warnings.append("This password contains repeated characters.")

    missing = []
    if not any(char.islower() for char in password):
        missing.append("lowercase letter")
    if not any(char.isupper() for char in password):
        missing.append("uppercase letter")
    if not any(char.isdigit() for char in password):
        missing.append("digit")
    if not any(char in string.punctuation for char in password):
        missing.append("special character")
    if missing:
        suggestions.append(f"Include at least one {', '.join(missing)}.")

    pool = _character_pool_size(password)
    entropy = round(length * math.log2(pool), 1) if pool else 0.0

    score = 0
    if length >= 8:
        score += 1
    if length >= 12:
        score += 1
    if entropy >= 16:
        score += 1
    if len(missing) <= 2:
        score += 1
    if len(missing) == 0:
        score += 1
    if warnings:
        score = max(0, score - min(2, len(warnings)))
    if lowered in COMMON_PASSWORDS:
        score = 0

    labels = ["very weak", "weak", "moderate", "strong", "very strong"]
    label = labels[min(score, len(labels) - 1)]
    if not suggestions and score >= 4:
        suggestions.append("Your password is strong. Do not reuse it on another account")

    return AnalysisResult(score, label, length, entropy, warnings, suggestions)
