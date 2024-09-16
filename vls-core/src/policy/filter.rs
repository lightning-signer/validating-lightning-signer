use serde::Deserialize;

use crate::prelude::*;

/// A result of a filter evaluation
#[derive(Copy, Clone, PartialEq, Debug, Deserialize)]
pub enum FilterResult {
    /// Policy should error
    Error,
    /// Policy should warn
    Warn,
}

/// A policy filter rule
#[derive(Clone, Debug, Deserialize)]
pub struct FilterRule {
    /// The tag or tag prefix
    pub tag: String,
    /// Whether the tag string should be considered a prefix
    pub is_prefix: bool,
    /// Whether a policy violation matching this rule should be demoted to a warning
    pub action: FilterResult,
}

impl FilterRule {
    /// Create a new warning filter rule
    pub fn new_warn(tag: impl Into<String>) -> FilterRule {
        FilterRule { tag: tag.into(), is_prefix: false, action: FilterResult::Warn }
    }

    /// Create a new erroring filter rule
    pub fn new_error(tag: impl Into<String>) -> FilterRule {
        FilterRule { tag: tag.into(), is_prefix: false, action: FilterResult::Error }
    }
}

/// A policy filter.
/// The default policy is to handle all policies as errors
#[derive(Clone, Debug, Deserialize)]
pub struct PolicyFilter {
    /// The rules, processed in the order they appear in this vector.
    /// The first match stops processing.
    pub rules: Vec<FilterRule>,
}

impl PolicyFilter {
    /// Evaluate the filter rules and return the resulting action
    pub fn filter(&self, tag: impl Into<String>) -> FilterResult {
        let tag = tag.into();
        for rule in self.rules.iter() {
            let matches = if rule.is_prefix { tag.starts_with(&rule.tag) } else { tag == rule.tag };
            if matches {
                return rule.action;
            }
        }
        FilterResult::Error
    }

    /// Create a filter that demotes all policy violations to warnings
    pub fn new_permissive() -> PolicyFilter {
        PolicyFilter {
            rules: vec![FilterRule {
                tag: "".to_string(),
                is_prefix: true,
                action: FilterResult::Warn,
            }],
        }
    }

    /// Merge another filter into this one.
    /// Rules in this filter takes precedence over rules in the other filter.
    pub fn merge(&mut self, other: PolicyFilter) {
        self.rules.extend(other.rules.into_iter());
    }
}

impl Default for PolicyFilter {
    fn default() -> Self {
        PolicyFilter { rules: vec![] }
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::filter::{FilterResult, FilterRule, PolicyFilter};

    #[test]
    fn test_default() {
        assert_eq!(PolicyFilter::default().filter("anything"), FilterResult::Error);
    }

    #[test]
    fn test_warn() {
        let filter = PolicyFilter {
            rules: vec![
                FilterRule {
                    tag: "abc-xyz".to_string(),
                    is_prefix: false,
                    action: FilterResult::Warn,
                },
                FilterRule { tag: "mno-".to_string(), is_prefix: true, action: FilterResult::Warn },
            ],
        };
        assert_eq!(filter.filter("abc-xyz1"), FilterResult::Error);
        assert_eq!(filter.filter("abc-xyz"), FilterResult::Warn);
        assert_eq!(filter.filter("mno-"), FilterResult::Warn);
        assert_eq!(filter.filter("mno-abc"), FilterResult::Warn);
        assert_eq!(filter.filter("anything"), FilterResult::Error);
    }

    #[test]
    fn test_warn_all() {
        let filter = PolicyFilter::new_permissive();
        assert_eq!(filter.filter("anything"), FilterResult::Warn);
    }
}
