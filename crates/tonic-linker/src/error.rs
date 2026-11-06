use std::fmt;

#[derive(Debug)]
pub enum LoadError {
    Io(std::io::Error),
    Elf(String),
    Unsupported(String),
    MissingSymbols(Vec<String>),
    MissingNeeded(Vec<String>),
    Mmap { what: String, errno: i32 },
    BadRelocation { offset: u64, detail: String },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Io(error) => write!(f, "reading file: {error}"),
            LoadError::Elf(message) => write!(f, "malformed ELF: {message}"),
            LoadError::Unsupported(message) => write!(f, "unsupported: {message}"),
            LoadError::MissingSymbols(names) => {
                write!(f, "{} unresolved symbol(s):", names.len())?;
                for name in names.iter().take(20) {
                    write!(f, "\n  - {name}")?;
                }
                if names.len() > 20 {
                    write!(f, "\n  ... and {} more", names.len() - 20)?;
                }
                Ok(())
            }
            LoadError::MissingNeeded(names) => {
                write!(f, "{} missing shared library dependency(ies):", names.len())?;
                for name in names {
                    write!(f, "\n  - {name}")?;
                }
                Ok(())
            }
            LoadError::Mmap { what, errno } => {
                write!(f, "address-space operation failed during {what} (errno {errno})")
            }
            LoadError::BadRelocation { offset, detail } => {
                write!(f, "relocation at {offset:#x}: {detail}")
            }
        }
    }
}

impl std::error::Error for LoadError {}

impl From<std::io::Error> for LoadError {
    fn from(error: std::io::Error) -> Self {
        LoadError::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, LoadError>;
