"""Run safe attack simulations against the test agent."""


@dataclass
class AttackCase:
    """A single attack case to run against the test agent."""
    attack_type: str
    
