//! # sd_jwt
//!
//! `sd_jwt` is an implementation of the [SD-JWT](https://www.ietf.org/archive/id/draft-fett-oauth-selective-disclosure-jwt-02.html) draft.
//! Not ready for production yet.

use base64;
use constant_time_eq::constant_time_eq;
use josekit::{
    jwk::alg::rsa::RsaKeyPair,
    jwk::Jwk,
    jws::{JwsHeader, RS256},
    jwt::{self, JwtPayload},
    JoseError,
};
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::str;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SDError {
    #[error("Combined presentaion is missing data.")]
    MissingData,
    #[error("Missing aud or nonce.")]
    MissingAudNonce,
    #[error("Error in signature validating: {0}")]
    JWTError(String),
    #[error("Missing _sd claim in the JWT.")]
    SDClaimMissing,
    #[error("Missing sub_jwk dictionary in JWT.")]
    SubJwkMissing,
    #[error("Issuer not matching in the JWT.")]
    IssuerError,
    #[error("Holdering binding key is not matching in SD-JWT-RELEASE.")]
    BindingKeyError,
    #[error("aud value is not matching.")]
    AudError,
    #[error("nonce value is not matching")]
    NonceError,
    #[error("No selective disclosure claims in SD-JWT-Release")]
    SDJwtReleaseError,
    #[error("Claims are not matching. {0} != {1}")]
    DigestError(String, String),
    #[error("Released claimed value is not a list.")]
    ReleasedClaimListError,
    #[error("Released claimed value does not have 2 entries.")]
    ReleasedClaimLengthError,
    #[error("Missing value in an option/JSON datastructure")]
    MissingValueError,
    #[error("Error in JSON convertion: {0}")]
    JsonError(String),
    #[error("Base64 encoding/decoding error.")]
    Base64Error,
    #[error("UTF-8 convertion error.")]
    Utf8Error,
}

impl std::convert::From<JoseError> for SDError {
    fn from(err: JoseError) -> Self {
        SDError::JWTError(err.to_string())
    }
}

impl std::convert::From<serde_json::Error> for SDError {
    fn from(err: serde_json::Error) -> Self {
        SDError::JsonError(err.to_string())
    }
}

impl std::convert::From<base64::DecodeError> for SDError {
    fn from(_err: base64::DecodeError) -> Self {
        SDError::Base64Error
    }
}

impl std::convert::From<std::str::Utf8Error> for SDError {
    fn from(_err: std::str::Utf8Error) -> Self {
        SDError::Utf8Error
    }
}

type Result<T> = std::result::Result<T, SDError>;

/// Returns a random base64 encoded String which can be used
/// as salt.
pub fn generate_salt() -> String {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut data = [0u8; 16];
    rng.fill_bytes(&mut data);
    base64_url::encode(&data)
}

/// Returns a `JWK` object from a PEM file content.
pub fn get_public_key(key_material: &Vec<u8>) -> Result<Jwk> {
    let keypair = RsaKeyPair::from_pem(key_material)?;
    Ok(keypair.to_jwk_public_key())
}

fn walk_by_structure<T>(structure: Value, obj: Value, func: &T) -> Result<Value>
where
    T: Fn(Value, Value, Value) -> Result<Value>,
{
    let mut out = serde_json::Map::new();

    let sturcture_obj = match structure.as_object() {
        Some(val) => val,
        None => return Err(SDError::MissingValueError),
    };

    let iter_obj = match obj.as_object() {
        Some(val) => val,
        None => return Err(SDError::MissingValueError),
    };

    // Now we can safely loop over the map
    for (key, value) in iter_obj.iter() {
        if sturcture_obj.contains_key(key) {
            let structure_value = sturcture_obj[key].clone();
            if structure_value.is_object() {
                out.insert(
                    String::from(key),
                    walk_by_structure(structure_value, value.clone(), func)?,
                );
            } else if structure_value.is_array() {
                // Empty list for results
                let mut list_res: Vec<Value> = Vec::new();
                let temp_value_array = match value.as_array() {
                    Some(val) => val,
                    None => return Err(SDError::MissingValueError),
                };
                // Now we can safely loop over the array
                for item in temp_value_array {
                    let structure_value_inside = structure_value
                        .as_array()
                        .ok_or(SDError::MissingValueError)?
                        .get(0)
                        .ok_or(SDError::MissingValueError)?
                        .clone();
                    list_res.push(walk_by_structure(
                        structure_value_inside,
                        item.clone(),
                        func,
                    )?);
                }
            } else {
                out.insert(
                    String::from(key),
                    func(
                        Value::String(key.to_string()),
                        value.clone(),
                        structure_value,
                    )?,
                );
            }
        } else {
            out.insert(
                String::from(key),
                func(Value::String(key.to_string()), value.clone(), Value::Null)?,
            );
        }
    }

    Ok(Value::Object(out))
}

fn hash_claim(salt: Value, value: Value, raw: bool) -> std::string::String {
    let raw_value = Value::Array(vec![salt, value]);
    let raw_string = raw_value.to_string();
    if raw {
        return raw_string;
    };
    hash_raw(&raw_string)
}

// Takes a raw string, hash it and returns the
// base64url value as string.
fn hash_raw(raw_string: &str) -> std::string::String {
    let mut hasher = Sha256::new();
    hasher.update(raw_string.as_bytes());
    let result = hasher.finalize();

    base64_url::encode(&result)
}

fn check_claim(_name: Value, released: Value, claimed_value: Value) -> Result<Value> {
    let hashed_value = hash_raw(released.as_str().ok_or(SDError::MissingValueError)?);
    let claimed_hash = claimed_value.as_str().ok_or(SDError::MissingValueError)?;
    if !constant_time_eq(hashed_value.as_bytes(), claimed_hash.as_bytes()) {
        return Err(SDError::DigestError(hashed_value, claimed_hash.to_string()));
    }
    let released_values: Value = match released.as_str() {
        Some(val) => serde_json::from_str(val)?,
        None => return Err(SDError::ReleasedClaimListError),
    };

    let released_values = released_values
        .as_array()
        .ok_or(SDError::MissingValueError)?;
    if released_values.len() != 2 {
        return Err(SDError::ReleasedClaimLengthError);
    }

    Ok(released_values[1].clone())
}

fn internal_hash(raw_value: &Value) -> Result<std::string::String> {
    let encoded = serde_json::ser::to_string_pretty(raw_value)?;
    Ok(base64_url::encode(&encoded))
}

/// Returns a Value, sd-jwt as serialized string, SVC value, and svc as serialized string.
///
/// # Arguments
///
/// * `issuer` - The issuer RSA certificate as a reference to Vec<u8>.
/// * `issuer_url` - The reference to the issuer URL.
/// * `user_claims` - The map of user claims to be added in the JWT.
/// * `exp` - Optional expiration value as u64.
/// * `holder` - Optional holder binding public key
pub fn create_sd_jwt(
    issuer: &Vec<u8>,
    issuer_url: &str,
    user_claims: Value,
    exp: Option<u64>,
    holder: Option<&Vec<u8>>,
) -> Result<(Value, String, Value, String)> {
    let signer = RS256.signer_from_pem(issuer)?;

    let gen_salts_lambda = |_: Value, _: Value, _: Value| Ok(Value::String(generate_salt()));
    let sd_claims_lambda = |_: Value, v, salt| Ok(Value::String(hash_claim(salt, v, false)));
    let sd_svc_lambda = |_: Value, v, salt| Ok(Value::String(hash_claim(salt, v, true)));

    // Let us get the salts
    let salts = walk_by_structure(
        Value::Object(serde_json::Map::new()),
        user_claims.clone(),
        &gen_salts_lambda,
    )?;

    let sd_claims = walk_by_structure(salts.clone(), user_claims.clone(), &sd_claims_lambda)?;
    let mut svc_payload_map = serde_json::Map::new();
    svc_payload_map.insert(
        "sd_release".into(),
        walk_by_structure(salts, user_claims, &sd_svc_lambda)?,
    );
    let svc_payload = Value::Object(svc_payload_map);

    let svc_payload_serialized = internal_hash(&svc_payload)?;

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let mut payload = JwtPayload::new();
    // TODO: sub value must be updated later
    payload.set_subject("subject");
    payload.set_issuer(issuer_url);

    // For now fixed iat and exp
    let now = SystemTime::now();
    payload.set_issued_at(&now);

    if let Some(exp_value) = exp {
        let exp_as_number: serde_json::Value = exp_value.into();
        payload.set_claim("exp", Some(exp_as_number))?;
    };

    // Set the holder binding key
    if let Some(holder_key_pem) = holder {
        let holder_public_key = get_public_key(holder_key_pem)?;
        let jwk_value: serde_json::Map<String, Value> = holder_public_key.into();
        payload.set_claim("sub_jwk", Some(Value::Object(jwk_value)))?;
    }
    // Add the hash_alg claim
    payload.set_claim("hash_alg", Some(Value::String("sha-256".to_string())))?;
    // Now add the salted values
    payload.set_claim("sd_digests", Some(sd_claims))?;

    let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

    return Ok((
        Value::Object(payload.claims_set().clone()),
        jwt,
        svc_payload,
        svc_payload_serialized,
    ));
}

/// Returns the sd-jwt-release value and serialized string.
///
/// # Arguments
///
/// * `nonce` - The nonce value as String.
/// * `aud` - The expected audience of the released JWT.
/// * `disclosed_claims` - The claims we are going to disclose.
/// * `svc_payload_serialized` - The serialized SVC payload
/// * `holder` - The reference to the holder's key.
pub fn create_sd_jwt_release(
    nonce: String,
    aud: String,
    disclosed_claims: Value,
    svc_payload_serialized: String,
    holder: &Vec<u8>,
) -> Result<(Value, std::string::String)> {
    let keypair = RsaKeyPair::from_pem(holder)?;
    let public_key = keypair.to_jwk_public_key();
    let signer = RS256.signer_from_pem(holder)?;

    let decoded_vec = base64_url::decode(&svc_payload_serialized)?;
    let decoded = str::from_utf8(&decoded_vec)?;
    let svc_claims_outer: Value = serde_json::from_str(decoded)?;
    let svc_raw_values = svc_claims_outer
        .as_object()
        .ok_or(SDError::MissingValueError)?
        .get("sd_release")
        .ok_or(SDError::MissingValueError)?;

    let get_raw_lambda = |_: Value, _: Value, raw: Value| Ok(raw);

    let mut header = JwsHeader::new();
    header.set_token_type("JWT");

    let _jwk_value: serde_json::Map<String, Value> = public_key.into();
    let mut payload = JwtPayload::new();
    // Set nonce & aud
    payload.set_claim("nonce", Some(Value::String(nonce)))?;
    payload.set_claim("aud", Some(Value::String(aud)))?;

    // We don't need the public key in SD-JWT-RELEASE for now
    // payload
    //     .set_claim("sub_jwk", Some(Value::Object(jwk_value)))
    //     .unwrap();

    let svc_disclosed_claims =
        walk_by_structure(svc_raw_values.clone(), disclosed_claims, &get_raw_lambda)?;
    // Now add the svc_disclised_claims
    payload.set_claim("sd_release", Some(svc_disclosed_claims))?;

    let sd_jwt_release = jwt::encode_with_signer(&payload, &header, &signer)?;
    return Ok((Value::Object(payload.claims_set().clone()), sd_jwt_release));
}

/// Verifies the given sd-jwt-release and returns the verified claims as `serde_json::Value`.
///
/// # Arguments
///
/// * `presentation` - A reference to the combined representation.
/// * `issuer_public_key` - Reference to the issuer's public key material.
/// * `issuer_details` - The issuer URL which will be verified.
/// * `holder_public_key` - Optional, if given it will matched against.
/// * `aud` - Optional audience value to be verified.
/// * `nonce` - Optional nonce value to be verified.
pub fn verify(
    presentation: &str,
    issuer_public_key: &[u8],
    issuer_details: &str,
    holder_public_key: Option<&Vec<u8>>,
    aud: Option<&str>,
    nonce: Option<&str>,
) -> Result<Value> {
    // If we are verifying the holder binding, then aud & nonce is must.

    if holder_public_key.is_some() && (aud.is_none() || nonce.is_none()) {
        return Err(SDError::MissingAudNonce);
    }

    // For now we assume that SD-JWT is signed by holder.
    let parts: Vec<&str> = presentation.split('.').collect();
    if parts.len() != 6 {
        return Err(SDError::MissingData);
    }

    // Let us first get the issuer's public key

    let issuer_keypair = RsaKeyPair::from_pem(issuer_public_key)?;
    let issuer_public_key = issuer_keypair.to_jwk_public_key();

    // This is the sd-jwt
    let input_jwd = parts[..3].join(".");
    // This is the sd-jwt-release
    let input_release_payload = parts[3..].join(".");
    let (payload, _header) = verify_sd_jwt(&input_jwd, issuer_public_key, issuer_details)?;

    // TODO: JWT header should not be None.

    let sd_jwt_claims = match payload.claim("sd_digests") {
        Some(claims) => claims.clone(),
        None => {
            return Err(SDError::SDClaimMissing);
        }
    };

    // Let us try to get the holder's public key material from the payload
    let holder_public_jwk: Option<Jwk> = match payload.claim("sub_jwk") {
        Some(value) => {
            let key_materials = if let Some(data) = value.as_object() {
                data
            } else {
                return Err(SDError::SubJwkMissing);
            };

            Some(Jwk::from_map(key_materials.clone())?)
        }
        None => None,
    };

    let sd_jwt_release_claims = verify_sd_jwt_release(
        &input_release_payload,
        holder_public_key,
        holder_public_jwk,
        aud,
        nonce,
    )?;

    walk_by_structure(sd_jwt_claims, sd_jwt_release_claims, &check_claim)
}

// fn check_claims(name: Value, released: Value, claim_value: Value) -> Result<Value> {
// }

fn verify_sd_jwt_release(
    jwt: &str,
    hpk: Option<&Vec<u8>>,
    hpk_payload: Option<Jwk>,
    aud: Option<&str>,
    nonce: Option<&str>,
) -> Result<Value> {
    // If we are checking for holdering binding then there must be sub_jwk
    if hpk.is_some() && hpk_payload.is_none() {
        return Err(SDError::SubJwkMissing);
    }

    let (payload, _header) = match hpk {
        Some(value) => {
            let holder_key = get_public_key(value)?;
            if let Some(key_from_payload) = hpk_payload {
                // Now match if this matches with the key from payload
                if holder_key != key_from_payload {
                    return Err(SDError::BindingKeyError);
                };
            }
            // Now let us create a verifier
            let verifier = RS256.verifier_from_jwk(&holder_key)?;

            // Now verify the signature
            jwt::decode_with_verifier(jwt, &verifier)?
        }
        None => jwt::decode_unsecured(jwt)?,
    };

    // Now verify the aud value
    if let Some(aud) = aud {
        match payload.claim("aud") {
            Some(aud_claim) => {
                if aud_claim.as_str().ok_or(SDError::MissingValueError)? != aud {
                    return Err(SDError::AudError);
                }
            }
            None => return Err(SDError::AudError),
        }
    }
    // Now verify the nonce value
    if let Some(nonce) = nonce {
        match payload.claim("nonce") {
            Some(nonce_claim) => {
                let ncs = nonce_claim.as_str().ok_or(SDError::MissingValueError)?;
                if ncs != nonce {
                    return Err(SDError::NonceError);
                }
            }
            None => return Err(SDError::NonceError),
        }
    }

    // Now verify that sd_release is there in the sd-jwt-release
    match payload.claim("sd_release") {
        Some(value) => Ok(value.clone()),
        None => Err(SDError::SDJwtReleaseError),
    }
}

fn verify_sd_jwt(jwt: &str, ipk: Jwk, issuer_details: &str) -> Result<(JwtPayload, JwsHeader)> {
    let verifier = RS256.verifier_from_jwk(&ipk)?;
    let (payload, header) = jwt::decode_with_verifier(jwt, &verifier)?;

    match payload.claim("iss") {
        Some(issuer) => {
            if issuer.as_str().ok_or(SDError::MissingValueError)? != issuer_details {
                return Err(SDError::IssuerError);
            }
        }
        None => {
            return Err(SDError::IssuerError);
        }
    }

    Ok((payload, header))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    fn test_fn(key: Value, value: Value, value_in_structure: Value) -> Result<Value> {
        let result = format!("called fn({}, {}, {})", key, value, value_in_structure);
        Ok(Value::String(result))
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

        let output = walk_by_structure(structure, user_claims, &test_fn).unwrap();
        let json_output = format!("{}", serde_json::ser::to_string_pretty(&output).unwrap());
        assert_eq!(result, json_output);
    }

    #[test]
    fn full_run() {
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
        let issuer_url = "https://example.com/issuer";
        let aud = "https://example.com/verifier".to_string();

        // Read the pem files for keys
        let issuer = std::fs::read("./issuer.pem").unwrap();
        let holder = std::fs::read("./holder.pem").unwrap();

        // Now create the SD-JWT
        let (_payload, jwt, _svc_payload, svc_serialized) = create_sd_jwt(
            &issuer,
            &issuer_url,
            user_claims,
            Some(1516247022),
            Some(&holder),
        )
        .unwrap();

        let (_sd_jwt_payload, sd_jwt_release) = create_sd_jwt_release(
            noanced.clone(),
            aud.clone(),
            disclosed_claims,
            svc_serialized,
            &holder,
        )
        .unwrap();

        let combined_presentation = format!("{}.{}", jwt, sd_jwt_release);

        let verified_values = verify(
            &combined_presentation,
            &issuer,
            issuer_url,
            Some(&holder),
            Some(&aud),
            Some(&noanced),
        )
        .unwrap();

        let result = serde_json::to_string(&verified_values).unwrap();
        let fixed_result = r#"{"given_name":"John","family_name":"Doe","address":{"street_address":"123 Main St","locality":"Anytown","region":"Anystate","country":"US"}}"#;
        assert_eq!(fixed_result, result);
    }
}
