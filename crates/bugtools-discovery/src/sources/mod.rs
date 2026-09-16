//! Discovery sources. Each is a native BugTools implementation.

pub mod certificate_transparency;
pub mod dns;

pub use certificate_transparency::CertificateTransparencySource;
pub use dns::DnsBruteForceSource;
