// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Private network validation and management.

use crate::{
    config::PrivateNetworkConfig,
    primitives::{RouterId, RouterInfo},
    crypto::base64_decode,
};

use hashbrown::HashSet;

/// Logging target for the file.
const LOG_TARGET: &str = "emissary::private_network";

/// Private network validator.
#[derive(Debug, Clone)]
pub struct PrivateNetworkValidator {
    /// Whether private network mode is enabled.
    enabled: bool,
    
    /// Set of known relay router IDs.
    known_relays: HashSet<RouterId>,
    
    /// Minimum bandwidth requirement for known relays.
    min_bandwidth: Option<String>,
}

impl PrivateNetworkValidator {
    /// Create a new private network validator.
    pub fn new(config: Option<&PrivateNetworkConfig>) -> Self {
        match config {
            Some(config) if config.enabled => {
                let known_relays = config
                    .known_relays
                    .iter()
                    .filter_map(|relay_str| {
                        // Parse router ID from string
                        // This assumes the string is base64 encoded router ID
                        base64_decode(relay_str.as_bytes())
                            .and_then(|bytes| {
                                if bytes.len() == 32 {
                                    let mut router_id = [0u8; 32];
                                    router_id.copy_from_slice(&bytes);
                                    Some(RouterId::from(router_id))
                                } else {
                                    None
                                }
                            })
                    })
                    .collect::<HashSet<_>>();

                tracing::info!(
                    target: LOG_TARGET,
                    known_relays_count = known_relays.len(),
                    "private network mode enabled with known relays"
                );

                Self {
                    enabled: true,
                    known_relays,
                    min_bandwidth: config.min_bandwidth.clone(),
                }
            }
            _ => Self {
                enabled: false,
                known_relays: HashSet::new(),
                min_bandwidth: None,
            },
        }
    }

    /// Check if private network mode is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Check if a router ID is a known relay.
    pub fn is_known_relay(&self, router_id: &RouterId) -> bool {
        self.known_relays.contains(router_id)
    }

    /// Check if a router can participate as a tunnel hop.
    /// In private network mode, only known relays can be tunnel hops.
    pub fn can_be_tunnel_hop(&self, router_id: &RouterId, router_info: &RouterInfo) -> bool {
        if !self.enabled {
            return true; // Normal I2P behavior when private network is disabled
        }

        // Only known relays can be tunnel hops
        if !self.is_known_relay(router_id) {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router rejected as tunnel hop: not a known relay"
            );
            return false;
        }

        // Check bandwidth requirements if specified
        if let Some(min_bandwidth) = &self.min_bandwidth {
            if !self.meets_bandwidth_requirement(router_info, min_bandwidth) {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    min_bandwidth = %min_bandwidth,
                    "router rejected as tunnel hop: insufficient bandwidth"
                );
                return false;
            }
        }

        // Additional checks for private network
        if !router_info.is_reachable() || !router_info.is_usable() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router rejected as tunnel hop: not reachable or usable"
            );
            return false;
        }

        true
    }

    /// Check if a router can participate as a floodfill node.
    /// In private network mode, only known relays can be floodfill nodes.
    pub fn can_be_floodfill(&self, router_id: &RouterId, router_info: &RouterInfo) -> bool {
        if !self.enabled {
            return router_info.is_floodfill(); // Normal I2P behavior
        }

        // Only known relays can be floodfill nodes
        if !self.is_known_relay(router_id) {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router rejected as floodfill: not a known relay"
            );
            return false;
        }

        // Must have floodfill capability
        if !router_info.is_floodfill() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router rejected as floodfill: no floodfill capability"
            );
            return false;
        }

        // Check bandwidth requirements if specified
        if let Some(min_bandwidth) = &self.min_bandwidth {
            if !self.meets_bandwidth_requirement(router_info, min_bandwidth) {
                tracing::debug!(
                    target: LOG_TARGET,
                    %router_id,
                    min_bandwidth = %min_bandwidth,
                    "router rejected as floodfill: insufficient bandwidth"
                );
                return false;
            }
        }

        true
    }

    /// Check if a router can be added to the routing table.
    /// In private network mode, only known relays can be added.
    pub fn can_be_added_to_routing_table(&self, router_id: &RouterId, router_info: &RouterInfo) -> bool {
        if !self.enabled {
            return true; // Normal I2P behavior
        }

        // Only known relays can be added to routing table
        if !self.is_known_relay(router_id) {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router rejected from routing table: not a known relay"
            );
            return false;
        }

        // Must be reachable and usable
        if !router_info.is_reachable() || !router_info.is_usable() {
            tracing::debug!(
                target: LOG_TARGET,
                %router_id,
                "router rejected from routing table: not reachable or usable"
            );
            return false;
        }

        true
    }

    /// Check if a router meets the minimum bandwidth requirement.
    fn meets_bandwidth_requirement(&self, router_info: &RouterInfo, min_bandwidth: &str) -> bool {
        let caps = &router_info.capabilities;
        
        match min_bandwidth {
            "O" | "P" | "X" => caps.is_fast(),
            _ => {
                tracing::warn!(
                    target: LOG_TARGET,
                    min_bandwidth = %min_bandwidth,
                    "unknown minimum bandwidth requirement"
                );
                false
            }
        }
    }

    /// Get the list of known relay router IDs.
    pub fn known_relays(&self) -> &HashSet<RouterId> {
        &self.known_relays
    }

    /// Get the number of known relays.
    pub fn known_relay_count(&self) -> usize {
        self.known_relays.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        primitives::{Capabilities, RouterIdentity},
        runtime::mock::MockRuntime,
    };
    use hashbrown::HashMap;

    fn create_test_router_info(caps: &str) -> RouterInfo {
        let (identity, _, _) = RouterIdentity::random();
        let capabilities = Capabilities::parse(&Str::from(caps)).unwrap();
        
        RouterInfo {
            identity,
            capabilities,
            addresses: HashMap::new(),
            net_id: 2,
            options: crate::primitives::Mapping::default(),
            published: crate::primitives::Date::new(0),
        }
    }

    #[test]
    fn private_network_disabled_allows_all() {
        let validator = PrivateNetworkValidator::new(None);
        let router_id = RouterId::random();
        let router_info = create_test_router_info("LR");

        assert!(!validator.is_enabled());
        assert!(validator.can_be_tunnel_hop(&router_id, &router_info));
        assert!(validator.can_be_added_to_routing_table(&router_id, &router_info));
    }

    #[test]
    fn private_network_enabled_blocks_unknown_routers() {
        let config = PrivateNetworkConfig {
            enabled: true,
            known_relays: vec!["test_relay_1".to_string()],
            min_bandwidth: None,
        };
        
        let validator = PrivateNetworkValidator::new(Some(&config));
        let router_id = RouterId::random();
        let router_info = create_test_router_info("LR");

        assert!(validator.is_enabled());
        assert!(!validator.can_be_tunnel_hop(&router_id, &router_info));
        assert!(!validator.can_be_added_to_routing_table(&router_id, &router_info));
    }

    #[test]
    fn bandwidth_requirement_enforcement() {
        let config = PrivateNetworkConfig {
            enabled: true,
            known_relays: vec!["test_relay_1".to_string()],
            min_bandwidth: Some("X".to_string()),
        };
        
        let validator = PrivateNetworkValidator::new(Some(&config));
        let router_id = RouterId::random();
        
        // Low bandwidth router should be rejected
        let low_bw_router = create_test_router_info("LR");
        assert!(!validator.can_be_tunnel_hop(&router_id, &low_bw_router));
        
        // High bandwidth router should be accepted
        let high_bw_router = create_test_router_info("XR");
        assert!(validator.can_be_tunnel_hop(&router_id, &high_bw_router));
    }
}
