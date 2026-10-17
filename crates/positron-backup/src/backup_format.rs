//! Independent Backup compatibility mapping owned by ADR-0060 and ADR-0026.
use crate::RepositoryFailure;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BackupFormatEpoch {
    LegacyPublication = 1,
    CaptureBound = 2,
}
impl BackupFormatEpoch {
    pub const NATIVE_WRITER: Self = Self::CaptureBound;
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::LegacyPublication),
            2 => Some(Self::CaptureBound),
            _ => None,
        }
    }
    pub const fn value(self) -> u32 {
        self as u32
    }
    pub const fn supports_independent_verification(self) -> bool {
        matches!(self, Self::CaptureBound)
    }
    pub(crate) const fn header(self) -> &'static [u8; 8] {
        match self {
            Self::LegacyPublication => b"POSBKM01",
            Self::CaptureBound => b"POSBKM02",
        }
    }
    pub(crate) fn from_header(header: &[u8]) -> Result<Self, RepositoryFailure> {
        match header {
            b"POSBKM01" => Ok(Self::LegacyPublication),
            b"POSBKM02" => Ok(Self::CaptureBound),
            _ => Err(RepositoryFailure::CorruptState),
        }
    }
}
