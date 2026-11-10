//! Every MPC_RELAY_* name in the README and the deploy manifests is one the
//! relay actually reads. The relay refuses to start on an unknown one, so a
//! stale name in a manifest would be a node that cannot start - and nothing
//! else compiles these files.

use mpc_relay::config::{is_kubernetes_service_link, KNOWN_VARS};

/// Misspellings the README uses on purpose, to show what is refused.
const DELIBERATE_TYPOS: &[&str] = &["MPC_RELAY_JWT_ISUER"];

fn names_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find("MPC_RELAY_") {
        let tail = &rest[i..];
        let end = tail
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(tail.len());
        out.push(tail[..end].trim_end_matches('_').to_owned());
        rest = &tail[end..];
    }
    out
}

#[test]
fn documented_and_deployed_variables_exist() {
    for file in [
        "README.md",
        "deploy/docker-compose.yml",
        "deploy/kubernetes.yaml",
        ".github/workflows/ci.yml",
    ] {
        let text = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("{file}: {e}"));
        for name in names_in(&text) {
            // The bare prefix (as in "MPC_RELAY_*"), and test-only knobs
            // read by the test harness rather than the relay.
            if name == "MPC_RELAY"
                || name.starts_with("MPC_RELAY_TEST_")
                || DELIBERATE_TYPOS.contains(&name.as_str())
                || is_kubernetes_service_link(&name)
            {
                continue;
            }
            assert!(
                KNOWN_VARS.contains(&name.as_str()),
                "{file} mentions {name}, which the relay does not read"
            );
        }
    }
}

#[test]
fn every_variable_is_documented() {
    let readme = std::fs::read_to_string("README.md").unwrap();
    for name in KNOWN_VARS {
        assert!(
            readme.contains(&format!("`{name}`")),
            "{name} is missing from the README's configuration reference"
        );
    }
}
