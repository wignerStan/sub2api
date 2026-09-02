use std::path::Path;

pub fn stable_digest(bytes: impl AsRef<[u8]>) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes.as_ref() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("fnv1a64:{hash:016x}")
}

pub fn normalize_slash_path(path: impl AsRef<str>) -> String {
    path.as_ref().replace('\\', "/")
}

pub fn normalize_path(path: &Path) -> String {
    normalize_slash_path(path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_stable() {
        assert_eq!(stable_digest("abc"), "fnv1a64:e71fa2190541574b");
        assert_eq!(stable_digest("abc".as_bytes()), stable_digest("abc"));
    }

    #[test]
    fn normalizes_backslashes() {
        assert_eq!(normalize_slash_path(r"src\lib.rs"), "src/lib.rs");
    }
}
