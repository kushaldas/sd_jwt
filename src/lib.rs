use base64_url;
use josekit::{
    jwk::alg::rsa::RsaKeyPair,
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use serde_json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str;

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

pub fn hash_claim(salt: Value, value: Value, raw: bool) -> std::string::String {
    let raw_value = Value::Array(vec![salt, value]);
    let raw_string = raw_value.to_string();
    if raw == true {
        return raw_string;
    };
    let mut hasher = Sha256::new();
    hasher.update(raw_string.as_bytes());
    let result = hasher.finalize();

    base64_url::encode(&result)
}

fn internal_hash(raw_value: &Value) -> std::string::String {
    let encoded = serde_json::ser::to_string_pretty(raw_value).unwrap();
    base64_url::encode(&encoded)
}

pub fn create_sd_jwt(
    issuer: &Vec<u8>,
    issuer_url: &str,
    user_claims: Value,
) -> (Value, String, Value, String) {
    let keypair = RsaKeyPair::from_pem(issuer).unwrap();
    let public_key = keypair.to_jwk_public_key();
    let signer = RS256.signer_from_pem(issuer).unwrap();

    let gen_salts_lambda = |_: Value, _: Value, _: Value| Value::String(generate_salt());
    let sd_claims_lambda = |_: Value, v, salt| Value::String(hash_claim(salt, v, false));
    let sd_svc_lambda = |_: Value, v, salt| Value::String(hash_claim(salt, v, true));

    // Let us get the salts
    let salts = walk_by_structure(
        Value::Object(serde_json::Map::new()),
        user_claims.clone(),
        &gen_salts_lambda,
    );

    let sd_claims = walk_by_structure(salts.clone(), user_claims.clone(), &sd_claims_lambda);
    let mut svc_payload_map = serde_json::Map::new();
    svc_payload_map.insert(
        "_sd".into(),
        walk_by_structure(salts, user_claims, &sd_svc_lambda),
    );
    let svc_payload = Value::Object(svc_payload_map);

    let svc_payload_serialized = internal_hash(&svc_payload);

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let jwk_value: serde_json::Map<String, Value> = public_key.into();
    let mut payload = JwtPayload::new();
    // TODO: sub value must be updated later
    payload.set_subject("subject");
    payload.set_issuer(issuer_url);

    // For now fixed iat and exp
    let iat_as_number: serde_json::Value = 1516239022.into();
    payload.set_claim("iat", Some(iat_as_number)).unwrap();
    let exp_as_number: serde_json::Value = 1516247022.into();
    payload.set_claim("exp", Some(exp_as_number)).unwrap();

    // Set the public key
    payload
        .set_claim("sub_jwk", Some(Value::Object(jwk_value)))
        .unwrap();

    // Now add the salted values
    payload.set_claim("_sd", Some(sd_claims)).unwrap();

    let jwt = jwt::encode_with_signer(&payload, &header, &signer).unwrap();

    return (
        Value::Object(payload.claims_set().clone()),
        jwt,
        svc_payload,
        svc_payload_serialized,
    );
}

pub fn create_sd_jwt_release(
    nonce: String,
    aud: String,
    disclosed_claims: Value,
    svc_payload_serialized: String,
    holder: &Vec<u8>,
) -> (Value, std::string::String) {
    let keypair = RsaKeyPair::from_pem(holder).unwrap();
    let public_key = keypair.to_jwk_public_key();
    let signer = RS256.signer_from_pem(holder).unwrap();

    let decoded_vec = base64_url::decode(&svc_payload_serialized).unwrap();
    let decoded = str::from_utf8(&decoded_vec).unwrap();
    let svc_claims_outer: Value = serde_json::from_str(&decoded).unwrap();
    let svc_raw_values = svc_claims_outer.as_object().unwrap().get("_sd").unwrap();

    let get_raw_lambda = |_: Value, _: Value, raw: Value| raw;

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let jwk_value: serde_json::Map<String, Value> = public_key.into();
    let mut payload = JwtPayload::new();
    // Set nonce & aud
    payload
        .set_claim("nonce", Some(Value::String(nonce)))
        .unwrap();
    payload.set_claim("aud", Some(Value::String(aud))).unwrap();

    // Set the public key
    payload
        .set_claim("sub_jwk", Some(Value::Object(jwk_value)))
        .unwrap();

    let svc_disclosed_claims =
        walk_by_structure(svc_raw_values.clone(), disclosed_claims, &get_raw_lambda);
    // Now add the svc_disclised_claims
    payload
        .set_claim("_sd", Some(svc_disclosed_claims))
        .unwrap();

    let sd_jwt_release = jwt::encode_with_signer(&payload, &header, &signer).unwrap();
    return (Value::Object(payload.claims_set().clone()), sd_jwt_release);
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
