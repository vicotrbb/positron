//! Representation compatibility of public ProtoJSON components. Component
//! round trips do not replace the request/response owners' semantic validation.
use positron_api::log_query::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::fmt::Debug;

fn snake_case(name: &str) -> String {
    let mut result = String::new();
    for character in name.chars() {
        if character.is_ascii_uppercase() {
            result.push('_');
            result.push(character.to_ascii_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}

fn representation<T>(expected: T, canonical: Value)
where
    T: Serialize + DeserializeOwned + PartialEq + Debug,
{
    assert_eq!(serde_json::to_value(&expected).expect("encode"), canonical);
    assert_eq!(
        serde_json::from_value::<T>(canonical.clone()).expect("decode"),
        expected
    );
    let fields = canonical.as_object().expect("message object");
    let mut aliases = serde_json::Map::new();
    for (name, value) in fields {
        aliases.insert(snake_case(name), value.clone());
        let key = serde_json::to_string(name).expect("field name");
        let value = serde_json::to_string(value).expect("field value");
        let duplicate = format!("{{{key}:{value},{key}:{value}}}");
        assert!(
            serde_json::from_str::<T>(&duplicate).is_err(),
            "duplicate {name}"
        );
        if snake_case(name) != *name {
            let alias = serde_json::to_string(&snake_case(name)).expect("alias");
            let duplicate_alias = format!("{{{key}:{value},{alias}:{value}}}");
            assert!(
                serde_json::from_str::<T>(&duplicate_alias).is_err(),
                "duplicate alias {name}"
            );
        }
    }
    assert_eq!(
        serde_json::from_value::<T>(Value::Object(aliases)).expect("aliases"),
        expected
    );
    assert!(serde_json::from_str::<T>(r#"{"unrecognizedField":"private-canary"}"#).is_err());
}

#[path = "protojson_contract/input_validation.rs"]
mod input_validation;
#[path = "protojson_contract/roundtrips.rs"]
mod roundtrips;

#[path = "protojson_contract/compatibility.rs"]
mod compatibility;
