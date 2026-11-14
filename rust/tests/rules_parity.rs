use std::collections::HashMap;
use std::path::PathBuf;

use aidf_core::rules::{load_rules, RuleEngine};
use serde_json::Value;

fn data_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join(name)
}

#[test]
fn every_rule_fires_on_its_fixture_and_stays_quiet_on_benign() {
    let text = std::fs::read_to_string(data_path("rule_cases.json")).unwrap();
    let cases: Vec<Value> = serde_json::from_str(&text).unwrap();
    let rules = load_rules(&[PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("rules")
        .join("base.json")
        .to_str()
        .unwrap()])
    .unwrap();
    let by_id: HashMap<&str, &aidf_core::rules::Rule> =
        rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();
    assert_eq!(cases.len(), 30);

    for case in cases {
        let rule_id = case["rule_id"].as_str().unwrap();
        let rule = by_id
            .get(rule_id)
            .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
        let mut engine = RuleEngine::new(vec![(*rule).clone()]).unwrap();
        let events = case["events"].as_array().unwrap();
        let mut fired = false;
        for event in events {
            let verdicts = engine.evaluate(event);
            if verdicts
                .iter()
                .any(|verdict| verdict.rule_id.as_deref() == Some(rule_id))
            {
                fired = true;
            }
        }
        assert!(fired, "{rule_id} did not fire on its own fixture");
        let benign = &case["benign"];
        let verdicts = engine.evaluate(benign);
        assert!(
            !verdicts
                .iter()
                .any(|verdict| verdict.rule_id.as_deref() == Some(rule_id)),
            "{rule_id} fired on the benign control"
        );
    }
}

