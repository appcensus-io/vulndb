from enum import Enum
from typing import Union

from pydantic import BaseModel
from pydantic import Field
from pydantic import RootModel


class Version(Enum):
    field_4_0 = "4.0"


class AttackVectorType(Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"


class ModifiedAttackVectorType(Enum):
    NETWORK = "NETWORK"
    ADJACENT = "ADJACENT"
    LOCAL = "LOCAL"
    PHYSICAL = "PHYSICAL"
    NOT_DEFINED = "NOT_DEFINED"


class AttackComplexityType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"


class ModifiedAttackComplexityType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    NOT_DEFINED = "NOT_DEFINED"


class AttackRequirementsType(Enum):
    NONE = "NONE"
    PRESENT = "PRESENT"


class ModifiedAttackRequirementsType(Enum):
    NONE = "NONE"
    PRESENT = "PRESENT"
    NOT_DEFINED = "NOT_DEFINED"


class PrivilegesRequiredType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"


class ModifiedPrivilegesRequiredType(Enum):
    HIGH = "HIGH"
    LOW = "LOW"
    NONE = "NONE"
    NOT_DEFINED = "NOT_DEFINED"


class UserInteractionType(Enum):
    NONE = "NONE"
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"


class ModifiedUserInteractionType(Enum):
    NONE = "NONE"
    PASSIVE = "PASSIVE"
    ACTIVE = "ACTIVE"
    NOT_DEFINED = "NOT_DEFINED"


class VulnCiaType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedVulnCiaType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class SubCiaType(Enum):
    NONE = "NONE"
    LOW = "LOW"
    HIGH = "HIGH"


class ModifiedSubCType(Enum):
    NEGLIGIBLE = "NEGLIGIBLE"
    LOW = "LOW"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ModifiedSubIaType(Enum):
    NEGLIGIBLE = "NEGLIGIBLE"
    LOW = "LOW"
    HIGH = "HIGH"
    SAFETY = "SAFETY"
    NOT_DEFINED = "NOT_DEFINED"


class ExploitMaturityType(Enum):
    UNREPORTED = "UNREPORTED"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    ATTACKED = "ATTACKED"
    NOT_DEFINED = "NOT_DEFINED"


class CiaRequirementType(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class SafetyType(Enum):
    NEGLIGIBLE = "NEGLIGIBLE"
    PRESENT = "PRESENT"
    NOT_DEFINED = "NOT_DEFINED"


class AutomatableType(Enum):
    NO = "NO"
    YES = "YES"
    NOT_DEFINED = "NOT_DEFINED"


class RecoveryType(Enum):
    AUTOMATIC = "AUTOMATIC"
    USER = "USER"
    IRRECOVERABLE = "IRRECOVERABLE"
    NOT_DEFINED = "NOT_DEFINED"


class ValueDensityType(Enum):
    DIFFUSE = "DIFFUSE"
    CONCENTRATED = "CONCENTRATED"
    NOT_DEFINED = "NOT_DEFINED"


class VulnerabilityResponseEffortType(Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    NOT_DEFINED = "NOT_DEFINED"


class ProviderUrgencyType(Enum):
    CLEAR = "CLEAR"
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"
    NOT_DEFINED = "NOT_DEFINED"


class NoneScoreType(RootModel[float]):
    root: float = 0.0


class LowScoreType(RootModel[float]):
    root: float = Field(..., ge=0.1, le=3.9, multiple_of=0.1)


class MediumScoreType(RootModel[float]):
    root: float = Field(..., ge=4.0, le=6.9, multiple_of=0.1)


class HighScoreType(RootModel[float]):
    root: float = Field(..., ge=7.0, le=8.9, multiple_of=0.1)


class CriticalScoreType(RootModel[float]):
    root: float = Field(..., ge=9.0, le=10.0, multiple_of=0.1)


class NoneSeverityType(RootModel[str]):
    root: str = "NONE"


class LowSeverityType(RootModel[str]):
    root: str = "LOW"


class MediumSeverityType(RootModel[str]):
    root: str = "MEDIUM"


class HighSeverityType(RootModel[str]):
    root: str = "HIGH"


class CriticalSeverityType(RootModel[str]):
    root: str = "CRITICAL"


SeverityType = Union[
    NoneSeverityType, LowSeverityType, MediumSeverityType, HighSeverityType, CriticalSeverityType
]
ScoreType = Union[NoneScoreType, LowScoreType, MediumScoreType, HighScoreType, CriticalScoreType]


class CVSS40(BaseModel):
    version: Version = Field(..., description="CVSS Version")
    vectorString: str = Field(
        ...,
        pattern=r"^CVSS:4[.]0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN](/E:[XAPU])?(/CR:[XHML])?(/IR:[XHML])?(/AR:[XHML])?(/MAV:[XNALP])?(/MAC:[XLH])?(/MAT:[XNP])?(/MPR:[XNLH])?(/MUI:[XNPA])?(/MVC:[XNLH])?(/MVI:[XNLH])?(/MVA:[XNLH])?(/MSC:[XNLH])?(/MSI:[XNLHS])?(/MSA:[XNLHS])?(/S:[XNP])?(/AU:[XNY])?(/R:[XAUI])?(/V:[XDC])?(/RE:[XLMH])?(/U:(X|Clear|Green|Amber|Red))?$",
    )
    attackVector: AttackVectorType | None = None
    attackComplexity: AttackComplexityType | None = None
    attackRequirements: AttackRequirementsType | None = None
    privilegesRequired: PrivilegesRequiredType | None = None
    userInteraction: UserInteractionType | None = None
    vulnConfidentialityImpact: VulnCiaType | None = None
    vulnIntegrityImpact: VulnCiaType | None = None
    vulnAvailabilityImpact: VulnCiaType | None = None
    subConfidentialityImpact: SubCiaType | None = None
    subIntegrityImpact: SubCiaType | None = None
    subAvailabilityImpact: SubCiaType | None = None
    exploitMaturity: ExploitMaturityType | None = ExploitMaturityType.NOT_DEFINED
    confidentialityRequirement: CiaRequirementType | None = CiaRequirementType.NOT_DEFINED
    integrityRequirement: CiaRequirementType | None = CiaRequirementType.NOT_DEFINED
    availabilityRequirement: CiaRequirementType | None = CiaRequirementType.NOT_DEFINED
    modifiedAttackVector: ModifiedAttackVectorType | None = ModifiedAttackVectorType.NOT_DEFINED
    modifiedAttackComplexity: ModifiedAttackComplexityType | None = (
        ModifiedAttackComplexityType.NOT_DEFINED
    )
    modifiedAttackRequirements: ModifiedAttackRequirementsType | None = (
        ModifiedAttackRequirementsType.NOT_DEFINED
    )
    modifiedPrivilegesRequired: ModifiedPrivilegesRequiredType | None = (
        ModifiedPrivilegesRequiredType.NOT_DEFINED
    )
    modifiedUserInteraction: ModifiedUserInteractionType | None = (
        ModifiedUserInteractionType.NOT_DEFINED
    )
    modifiedVulnConfidentialityImpact: ModifiedVulnCiaType | None = ModifiedVulnCiaType.NOT_DEFINED
    modifiedVulnIntegrityImpact: ModifiedVulnCiaType | None = ModifiedVulnCiaType.NOT_DEFINED
    modifiedVulnAvailabilityImpact: ModifiedVulnCiaType | None = ModifiedVulnCiaType.NOT_DEFINED
    modifiedSubConfidentialityImpact: ModifiedSubCType | None = ModifiedSubCType.NOT_DEFINED
    modifiedSubIntegrityImpact: ModifiedSubIaType | None = ModifiedSubIaType.NOT_DEFINED
    modifiedSubAvailabilityImpact: ModifiedSubIaType | None = ModifiedSubIaType.NOT_DEFINED
    Safety: SafetyType | None = SafetyType.NOT_DEFINED
    Automatable: AutomatableType | None = AutomatableType.NOT_DEFINED
    Recovery: RecoveryType | None = RecoveryType.NOT_DEFINED
    valueDensity: ValueDensityType | None = ValueDensityType.NOT_DEFINED
    vulnerabilityResponseEffort: VulnerabilityResponseEffortType | None = (
        VulnerabilityResponseEffortType.NOT_DEFINED
    )
    providerUrgency: ProviderUrgencyType | None = ProviderUrgencyType.NOT_DEFINED
    baseScore: ScoreType
    baseSeverity: SeverityType
    threatScore: ScoreType | None = None
    threatSeverity: SeverityType | None = None
    environmentalScore: ScoreType | None = None
    environmentalSeverity: SeverityType | None = None
