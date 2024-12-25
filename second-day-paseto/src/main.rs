use chrono::NaiveDateTime;
use pasetors::claims::{Claims, ClaimsValidationRules};
use pasetors::{local, Local, version4::V4};
use pasetors::footer::Footer;
use pasetors::keys::{Generate, SymmetricKey};
use pasetors::paserk::Id;

fn main() {
    println!("Hello, world!");
}

pub trait TokenHandler {
    fn new(iss: String, sub: String, aud: String, exp: chrono::DateTime<chrono::Utc>, nbf: chrono::DateTime<chrono::Utc>, iat: chrono::DateTime<chrono::Utc>, jti: String) -> Self;
    fn encrypt(&self, key: &str) -> String;
    fn decrypt(&self, key: &str) -> String;
}


// structure for Token data
pub struct Claim {
    iss: String, //
    sub: String,
    aud: String,
    exp: chrono::DateTime<chrono::Utc>,
    nbf: chrono::DateTime<chrono::Utc>,
    iat: chrono::DateTime<chrono::Utc>,
    jti: String,
}

impl TokenHandler for Claim {
    fn new(iss: String, sub: String, aud: String, exp: chrono::DateTime<chrono::Utc>, nbf: chrono::DateTime<chrono::Utc>, iat: chrono::DateTime<chrono::Utc>, jti: String) -> Self {
        Claim {
            iss,
            sub,
            aud,
            exp,
            nbf,
            iat,
            jti,
        }
    }

    fn encrypt(&self, key: &str) -> String {
        let mut claims = Claims::new().unwrap();

        claims.issuer(&self.iss).unwrap();
        claims.subject(&self.sub).unwrap();
        claims.audience(&self.aud).unwrap();
        claims.expiration(&self.exp.to_rfc3339()).unwrap();
        claims.not_before(&self.nbf.to_rfc3339()).unwrap();
        claims.issued_at(&self.iat.to_rfc3339()).unwrap();
        claims.token_identifier(&self.jti).unwrap();

        let sk = SymmetricKey::<V4>::generate().unwrap();

        let pid = Id::from(&sk);
        let mut footer = Footer::new();
        footer.key_id(&pid);

        let token = local::encrypt(&sk, &claims, Some(&footer), Some(b"implisit Assertion")).unwrap();
        token
    }

    fn decrypt(&self, key: &str) -> String {
        let token = "asdlkasd";
        token.to_string()
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let iss = "iss".to_string();
        let sub = "sub".to_string();
        let aud = "aud".to_string();
        let exp = chrono::Utc::now();
        let nbf = chrono::Utc::now();
        let iat = chrono::Utc::now();
        let jti = "jti".to_string();

        let claim = Claim::new(iss.clone(), sub.clone(), aud.clone(), exp.clone(), nbf.clone(), iat.clone(), jti.clone());

        assert_eq!(claim.iss, iss);
        assert_eq!(claim.sub, sub);
        assert_eq!(claim.aud, aud);
        assert_eq!(claim.exp, exp);
        assert_eq!(claim.nbf, nbf);
        assert_eq!(claim.iat, iat);
        assert_eq!(claim.jti, jti);
    }

    #[test]
    fn test_encrypt() {
        let iss = "iss".to_string();
        let sub = "sub".to_string();
        let aud = "aud".to_string();
        let exp = chrono::Utc::now();
        let nbf = chrono::Utc::now();
        let iat = chrono::Utc::now();
        let jti = "jti".to_string();

        let claim = Claim::new(iss, sub, aud, exp, nbf, iat, jti);

        let token = claim.encrypt("key");
        assert!(token.len() > 50);
    }

    #[test]
    fn test_decrypt() {
        let iss = "iss".to_string();
        let sub = "sub".to_string();
        let aud = "aud".to_string();
        let exp = chrono::Utc::now();
        let nbf = chrono::Utc::now();
        let iat = chrono::Utc::now();
        let jti = "jti".to_string();

        let claim = Claim::new(iss, sub, aud, exp, nbf, iat, jti);

        let token = claim.decrypt("key");

        assert_eq!(token, "token");
    }
}