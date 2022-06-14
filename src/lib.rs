use base64_url;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use serde_json;
use serde_json::{json, Error, Value};

pub fn generate_salt() -> String {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut data = [0u8; 16];
    rng.fill_bytes(&mut data);
    base64_url::encode(&data)
}

pub fn walk_by_structure<T>(structure: Value, obj: Value, func: &T) -> Value
where
    T: Fn(Value, Value, Value) -> Value,
{
    let mut out = serde_json::Map::new();

    let sturcture_obj = structure.as_object().unwrap();

    for (key, value) in obj.as_object().unwrap().iter() {
        if sturcture_obj.contains_key(key) {
            let structure_value = sturcture_obj[key].clone();
            if structure_value.is_object() {
                out.insert(
                    String::from(key),
                    walk_by_structure(structure_value, value.clone(), func),
                );
            } else if structure_value.is_array() {
                let mut list_res: Vec<Value> = Vec::new();
                for item in value.as_array().unwrap() {
                    let structure_value_inside = structure_value.as_array().unwrap()[0].clone();
                    list_res.push(walk_by_structure(
                        structure_value_inside,
                        item.clone(),
                        func,
                    ));
                }
            } else {
                out.insert(
                    String::from(key),
                    func(
                        Value::String(key.to_string()),
                        value.clone(),
                        structure_value,
                    ),
                );
            }
        } else {
            out.insert(
                String::from(key),
                func(Value::String(key.to_string()), value.clone(), Value::Null),
            );
        }
    }

    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn test_fn(key: Value, value: Value, value_in_structure: Value) -> Value {
        let result = format!("called fn({}, {}, {})", key, value, value_in_structure);
        Value::String(result)
    }
    #[test]
    fn first_check_for_simple_values() {
        let structure = Value::Object(serde_json::Map::new());

        let user_claims = json!( {
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "given_name": "John",
            "family_name": "Doe",
            "email": "johndoe@example.com",
            "phone_number": "+1-202-555-0101",
            "address": {
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US",
            },
            "birthdate": "1940-01-01",
        });

        let result = r#"{
  "sub": "called fn(\"sub\", \"6c5c0a49-b589-431d-bae7-219122a9ec2c\", null)",
  "given_name": "called fn(\"given_name\", \"John\", null)",
  "family_name": "called fn(\"family_name\", \"Doe\", null)",
  "email": "called fn(\"email\", \"johndoe@example.com\", null)",
  "phone_number": "called fn(\"phone_number\", \"+1-202-555-0101\", null)",
  "address": "called fn(\"address\", {\"street_address\":\"123 Main St\",\"locality\":\"Anytown\",\"region\":\"Anystate\",\"country\":\"US\"}, null)",
  "birthdate": "called fn(\"birthdate\", \"1940-01-01\", null)"
}"#;

        let output = walk_by_structure(structure, user_claims, &test_fn);
        let json_output = format!("{}", serde_json::ser::to_string_pretty(&output).unwrap());
        assert_eq!(result, json_output);
    }
}
