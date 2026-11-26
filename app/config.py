"""Runtime settings, read from environment variables.

VULN_MODE controls every intentional vulnerability in the app:
  - "vulnerable" (default): the insecure code paths run
  - "secure": the fixed code paths run
"""

import os
import secrets
from dataclasses import dataclass, field

VULNERABLE = "vulnerable"
SECURE = "secure"

# VULN-04 (weak / hardcoded secret): this is the kind of secret that ends up
# committed to a repo. In secure mode it is never used.
HARDCODED_JWT_SECRET = "changeme"


@dataclass
class Settings:
    mode: str = field(default_factory=lambda: os.getenv("VULN_MODE", VULNERABLE))
    db_path: str = field(default_factory=lambda: os.getenv("DB_PATH", "vuln_shop.db"))
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "fake"))
    ollama_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434")
    )
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1:8b"))
    jwt_secret: str = ""

    def __post_init__(self) -> None:
        if self.mode not in (VULNERABLE, SECURE):
            raise ValueError(f"VULN_MODE must be '{VULNERABLE}' or '{SECURE}', got {self.mode!r}")
        if not self.jwt_secret:
            if self.is_vulnerable:
                self.jwt_secret = HARDCODED_JWT_SECRET
            else:
                # Secure: a strong secret from the environment, or a random one per process.
                self.jwt_secret = os.getenv("JWT_SECRET") or secrets.token_hex(32)

    @property
    def is_vulnerable(self) -> bool:
        return self.mode == VULNERABLE
