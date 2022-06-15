use sd_jwt::create_sd_jwt;
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
    let _disclosed_claims: Value = serde_json::from_str(disclosed_claims_raw).unwrap();
    // for key in user_claims.as_object().unwrap().keys() {
    //     println!("{}", key);
    // }
    // dbg!(user_claims);
    let issuer_url = "https://example.com/issuer";
    let issuer = std::fs::read("./issuer.pem").unwrap();

    let (payload, jwt, svc_payload, svc_jwt) = create_sd_jwt(&issuer, &issuer_url, user_claims);

    println!(
        "The SD-JWT is:\n {}",
        serde_json::ser::to_string_pretty(&payload).unwrap()
    );
    println!("The serialized SD-JWT is:\n {}", jwt);
    println!(
        "The Payload SD-SVC is:\n {}",
        serde_json::ser::to_string_pretty(&svc_payload).unwrap()
    );
    println!("The serialized SD-SVC is:\n {}", svc_jwt);
}
