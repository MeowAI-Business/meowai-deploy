use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RemotePath(String);

impl RemotePath {
    pub fn parse(value: &str) -> Result<Self, RemotePathError> {
        if value.is_empty() || !value.starts_with('/') {
            return Err(RemotePathError::NotAbsolute);
        }
        if value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
            return Err(RemotePathError::ControlCharacter);
        }

        let mut components = Vec::new();
        for component in value.split('/') {
            match component {
                "" => {}
                "." | ".." => return Err(RemotePathError::UnsafeComponent),
                value => components.push(value),
            }
        }
        if components.is_empty() {
            return Err(RemotePathError::RootDirectory);
        }
        Ok(Self(format!("/{}", components.join("/"))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn join(&self, relative: &str) -> Result<Self, RemotePathError> {
        if relative.is_empty()
            || relative.starts_with('/')
            || relative
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
            || relative
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(RemotePathError::UnsafeComponent);
        }
        Self::parse(&format!("{}/{relative}", self.0))
    }
}

impl fmt::Display for RemotePath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RemotePath {
    type Err = RemotePathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for RemotePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RemotePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RemotePathError {
    #[error("remote deployment directory must be an absolute POSIX path")]
    NotAbsolute,
    #[error("remote deployment directory cannot be the filesystem root")]
    RootDirectory,
    #[error("remote deployment directory contains a control character")]
    ControlCharacter,
    #[error("remote deployment directory contains an unsafe path component")]
    UnsafeComponent,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_paths_normalize_repeated_separators_and_preserve_spaces() {
        let path = RemotePath::parse("//opt///meow ai/newapi").expect("remote path");
        assert_eq!(path.as_str(), "/opt/meow ai/newapi");
        assert_eq!(
            path.join("data/state.json").expect("joined path").as_str(),
            "/opt/meow ai/newapi/data/state.json"
        );
    }

    #[test]
    fn remote_paths_reject_relative_traversal_root_and_control_characters() {
        for value in [
            "opt/newapi",
            "/",
            "/opt/../root",
            "/opt/./newapi",
            "/opt\n/newapi",
        ] {
            assert!(RemotePath::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn remote_paths_serialize_as_compatible_strings() {
        let path = RemotePath::parse("/opt/meowai-deploy/newapi").expect("remote path");
        let encoded = serde_json::to_string(&path).expect("serialize path");
        assert_eq!(encoded, "\"/opt/meowai-deploy/newapi\"");
        assert_eq!(
            serde_json::from_str::<RemotePath>(&encoded).expect("deserialize path"),
            path
        );
    }
}
