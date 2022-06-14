use serde_json;
use serde_json::{json, Value};

fn main() {
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

    let disclosed_claims_raw = r#"
    {
        "given_name": "",
        "family_name": "",
        "address": ""
    }
    "#;
    let disclosed_claims: Value = serde_json::from_str(disclosed_claims_raw).unwrap();
    for key in user_claims.as_object().unwrap().keys() {
        println!("{}", key);
    }
    dbg!(user_claims);
}
