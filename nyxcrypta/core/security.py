from enum import Enum

class SecurityLevel(Enum):
    STANDARD = 1  # RSA 2048
    HIGH = 2  # RSA 3072
    PARANOID = 3  # RSA 4096
