//! NIP-11 relay information document (dialect.md §3). Owner: wp2-http.
//!
//! The client's "does this relay require membership?" test is literally "is 43
//! in supported_nips", so NIP-43 is advertised ONLY when membership is enforced
//! AND a stable signing key exists. `self` is the relay's stable pubkey.

use serde_json::json;

use crate::proto;
use crate::relay_identity::RelayIdentity;
use crate::settings::Settings;

/// Build the NIP-11 `RelayInfo` document as a JSON value.
pub fn document(settings: &Settings, identity: &RelayIdentity) -> serde_json::Value {
    let mut supported_nips = vec![1, 9, 11, 16, 42, 50];
    if settings.require_auth_token {
        supported_nips.push(98);
    }
    // advertise_nip43 = has_stable_key && require_relay_membership. The bridge
    // always has a stable key (D4), so membership enforcement is the gate.
    if settings.require_membership {
        supported_nips.push(43);
    }

    json!({
        "name": "x0x-nostr-bridge",
        "description": "Nostr relay dialect over the x0x gossip fabric (Buzz M1a)",
        "software": "x0x-nostr-bridge",
        "version": env!("CARGO_PKG_VERSION"),
        "supported_nips": supported_nips,
        "self": identity.public_key_hex(),
        "x0x_api_fingerprint": settings.x0x_api_fingerprint,
        "supported_extensions": ["nip-er"],
        "limitation": {
            "max_message_length": proto::MAX_FRAME_BYTES,
            "max_subscriptions": proto::MAX_SUBS_PER_CONN,
            "max_limit": 500,
            "auth_required": settings.require_auth_token,
            "restricted_writes": settings.require_membership,
            "payload_required": false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertises_self_and_base_nips() {
        let s = Settings::default();
        let id = RelayIdentity::ephemeral();
        let doc = document(&s, &id);
        // `self` is the relay's stable pubkey.
        assert_eq!(doc["self"], id.public_key_hex());
        let nips: Vec<i64> = doc["supported_nips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();
        for n in [1, 11, 16, 42, 50] {
            assert!(nips.contains(&n), "missing NIP-{n}");
        }
    }

    #[test]
    fn nip43_only_when_membership_enforced() {
        let id = RelayIdentity::ephemeral();
        // off by default
        let doc = document(&Settings::default(), &id);
        let nips = doc["supported_nips"].as_array().unwrap();
        assert!(!nips.iter().any(|v| v.as_i64() == Some(43)));
        // on when membership enforced
        let s = Settings {
            require_membership: true,
            ..Default::default()
        };
        let doc = document(&s, &id);
        let nips = doc["supported_nips"].as_array().unwrap();
        assert!(nips.iter().any(|v| v.as_i64() == Some(43)));
    }

    #[test]
    fn nip98_advertised_when_token_required() {
        let id = RelayIdentity::ephemeral();
        let s = Settings {
            require_auth_token: true,
            ..Default::default()
        };
        let doc = document(&s, &id);
        let nips = doc["supported_nips"].as_array().unwrap();
        assert!(nips.iter().any(|v| v.as_i64() == Some(98)));
    }
}
