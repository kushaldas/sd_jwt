use sd_jwt::{create_sd_jwt, create_sd_jwt_release, generate_salt, verify};
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

    let noanced = generate_salt();
    // for key in user_claims.as_object().unwrap().keys() {
    //     println!("{}", key);
    // }
    // dbg!(user_claims);
    let issuer_url = "https://example.com/issuer";
    let aud = "https://example.com/verifier".to_string();

    // Read the pem files for keys
    let issuer = std::fs::read("./issuer.pem").unwrap();
    let holder = std::fs::read("./holder.pem").unwrap();

    // Now create the SD-JWT
    let (payload, jwt, svc_payload, svc_serialized) = create_sd_jwt(
        &issuer,
        &issuer_url,
        user_claims,
        Some(1516247022),
        Some(&holder),
    )
    .unwrap();

    println!(
        "The SD-JWT is:\n {}",
        serde_json::ser::to_string_pretty(&payload).unwrap()
    );
    println!("The serialized SD-JWT is:\n {}", jwt);
    println!(
        "The Payload SD-SVC is:\n {}",
        serde_json::ser::to_string_pretty(&svc_payload).unwrap()
    );
    println!("The serialized SD-SVC is:\n {}", svc_serialized);

    println!("\n\n\n\n");

    let (sd_jwt_payload, sd_jwt_release) = create_sd_jwt_release(
        noanced.clone(),
        aud.clone(),
        disclosed_claims,
        svc_serialized,
        &holder,
    )
    .unwrap();
    println!(
        "The payload for SD-JWT-RELEASE:\n {}",
        serde_json::ser::to_string_pretty(&sd_jwt_payload).unwrap()
    );

    println!("The serialized SD-JWT-RELEASE is: \n {}", sd_jwt_release);

    let combined_presentation = format!("{}.{}", jwt, sd_jwt_release);
    println!(
        "\n\nThe combined presentation: \n\n{}\n\n",
        combined_presentation
    );

    let verified_values = verify(
        &combined_presentation,
        &issuer,
        issuer_url,
        Some(&holder),
        Some(&aud),
        Some(&noanced),
    )
    .unwrap();
    dbg!(verified_values);
}
