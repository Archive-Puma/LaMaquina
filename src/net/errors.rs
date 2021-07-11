use std::net::IpAddr;
use std::time::Duration;

#[derive(Debug)]
pub enum Error {
    DestinationUnreachable(IpAddr),
    InvalidAddress(String),
    NoResponse(IpAddr),
    PrivilegeRequired,
    Timeout(IpAddr, Duration),
    Unknown(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::DestinationUnreachable(address) => write!(f, "{} is unreachable", address),
            Error::InvalidAddress(address) => write!(f, "{} is not a valid address", address),
            Error::NoResponse(ip) => write!(f, "No response from {}", ip),
            Error::PrivilegeRequired => write!(f, "Permission denied"),
            Error::Timeout(address, time) => {
                write!(
                    f,
                    "Timeout connecting to {} ({}s)",
                    address,
                    time.as_secs_f64()
                )
            }
            Error::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn errors() {
        assert_eq!(
            Error::DestinationUnreachable("1.1.1.1".parse::<IpAddr>().unwrap()).to_string(),
            "1.1.1.1 is unreachable"
        );
        assert_eq!(
            Error::InvalidAddress("1.2.3.456".to_owned()).to_string(),
            "1.2.3.456 is not a valid address"
        );
        assert_eq!(
            Error::NoResponse("127.0.0.1".parse::<IpAddr>().unwrap()).to_string(),
            "No response from 127.0.0.1"
        );
        assert_eq!(Error::PrivilegeRequired.to_string(), "Permission denied");
        assert_eq!(
            Error::Timeout(
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                Duration::from_secs(20)
            )
            .to_string(),
            "Timeout connecting to 1.1.1.1 (20s)"
        );
        assert_eq!(
            Error::Unknown("weirdo".to_owned()).to_string(),
            "Unknown error: weirdo"
        );
    }
}
