use bgp_packet::{
    nlri::NLRI,
    path_attributes::{LargeCommunitiesPathAttribute, PathAttribute},
};

use crate::config::{FilterAction, FilterMatcher, UpdateAction};

pub struct FilterEvaluator {
    filter_in: Vec<(FilterMatcher, FilterAction)>,
    filter_out: Vec<(FilterMatcher, FilterAction)>,
}

impl FilterEvaluator {
    pub fn new(
        filter_in: Vec<(FilterMatcher, FilterAction)>,
        filter_out: Vec<(FilterMatcher, FilterAction)>,
    ) -> Self {
        Self {
            filter_in,
            filter_out,
        }
    }

    fn check_rule_match(
        matcher: &FilterMatcher,
        path_attributes: &Vec<PathAttribute>,
        as_path: &Vec<u32>,
        nlri: &NLRI,
    ) -> bool {
        if let Some(matcher_nlri) = &matcher.nlri {
            if nlri != matcher_nlri {
                return false;
            }
        }
        if let (Some(matcher_origin_asn), Some(origin_asn)) = (matcher.origin_asn, as_path.last()) {
            if matcher_origin_asn != *origin_asn {
                return false;
            }
        }
        if let Some(matcher_large_community) = &matcher.large_community {
            let mut found = false;
            for attribute in path_attributes {
                if let PathAttribute::LargeCommunitiesPathAttribute(lcs) = attribute {
                    if lcs.values.iter().any(|lc| lc == matcher_large_community) {
                        found = true;
                        break;
                    }
                }
            }
            if !found {
                return false;
            }
        }

        return true;
    }

    fn apply_update(update_action: &UpdateAction, path_attributes: &mut Vec<PathAttribute>) {
        match update_action {
            UpdateAction::AttachLargeCommunity(large_community) => {
                let mut added_existing = false;
                for path_attribute in &mut *path_attributes {
                    if let PathAttribute::LargeCommunitiesPathAttribute(lc_attr) = path_attribute {
                        lc_attr.values.push(large_community.clone());
                        added_existing = true;
                    }
                }
                if !added_existing {
                    path_attributes.push(PathAttribute::LargeCommunitiesPathAttribute(
                        LargeCommunitiesPathAttribute {
                            values: vec![large_community.clone()],
                        },
                    ))
                }
            }
        }
    }

    fn evaluate(
        rules: &Vec<(FilterMatcher, FilterAction)>,
        path_attributes: &mut Vec<PathAttribute>,
        as_path: &Vec<u32>,
        nlri: &NLRI,
    ) -> bool {
        for rule in rules {
            if Self::check_rule_match(&rule.0, path_attributes, as_path, nlri) {
                match &rule.1 {
                    FilterAction::Accept => return true,
                    FilterAction::Reject => return false,
                    FilterAction::Update(update_action) => {
                        Self::apply_update(update_action, path_attributes)
                    }
                }
            }
        }

        // Default behavior is to deny.
        return false;
    }

    /// evaluate_in checks if an announced route is eligible to be accepted into the Loc-RIB.
    /// Note that this may change the path_attributes if a FilterAction requests to do so.
    pub fn evaluate_in(
        &self,
        path_attributes: &mut Vec<PathAttribute>,
        as_path: &Vec<u32>,
        nlri: &NLRI,
    ) -> bool {
        Self::evaluate(&self.filter_in, path_attributes, as_path, nlri)
    }

    /// evaluate_out checks if a route from the Loc-RIB is to be announced to a peer.
    /// Note that this may change the path_attributes if a FilterAction requests to do so.
    pub fn evaluate_out(
        &self,
        path_attributes: &mut Vec<PathAttribute>,
        as_path: &Vec<u32>,
        nlri: &NLRI,
    ) -> bool {
        Self::evaluate(&self.filter_out, path_attributes, as_path, nlri)
    }
}

#[cfg(test)]
mod tests {
    use bgp_packet::nlri::NLRI;

    use crate::config::{FilterAction, FilterMatcher};

    use super::FilterEvaluator;

    #[test]
    fn test_simple_match_nlri() {
        let nlri = NLRI::try_from("2001:db8::/48").unwrap();
        let matcher = FilterEvaluator::new(
            vec![(
                FilterMatcher {
                    nlri: Some(nlri.clone()),
                    origin_asn: None,
                    large_community: None,
                },
                FilterAction::Accept,
            )],
            vec![],
        );

        assert!(matcher.evaluate_in(&mut vec![], &vec![], &nlri));
    }

    #[test]
    fn test_simple_match_origin_asn() {
        let matcher = FilterEvaluator::new(
            vec![(
                FilterMatcher {
                    nlri: None,
                    origin_asn: Some(65000),
                    large_community: None,
                },
                FilterAction::Accept,
            )],
            vec![],
        );

        assert!(matcher.evaluate_in(
            &mut vec![],
            &vec![65000],
            &NLRI::try_from("2001:db8::/48").unwrap()
        ));
    }

    #[test]
    fn test_targeted_deny() {
        let bad_nlri = NLRI::try_from("2001:db8:bad::/48").unwrap();
        let matcher = FilterEvaluator::new(
            vec![
                // Reject a specific prefix 2001:db8:bad::/48
                (
                    FilterMatcher {
                        nlri: Some(bad_nlri.clone()),
                        origin_asn: None,
                        large_community: None,
                    },
                    FilterAction::Reject,
                ),
                // Accept everything else.
                (
                    FilterMatcher {
                        nlri: None,
                        origin_asn: None,
                        large_community: None,
                    },
                    FilterAction::Accept,
                ),
            ],
            vec![],
        );

        assert!(!matcher.evaluate_in(&mut vec![], &vec![], &bad_nlri));
        assert!(matcher.evaluate_in(
            &mut vec![],
            &vec![],
            &NLRI::try_from("2001:db8:1234::/48").unwrap()
        ));
    }
}
