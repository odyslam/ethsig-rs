use ethers::types::{Signature, H160};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use siwe::Message;
use std::str::FromStr;
use worker::*;

/// All authentication requests are compromised of two elements:
/// a) A message that follows EIP4361
/// b) A signature of said message
///
/// EIP4361 Template:
/// ```
/// ${domain} wants you to sign in with your Ethereum account:
/// ${address}
///
/// ${statement}
///
/// URI: ${uri}
/// Version: ${version}
/// Chain ID: ${chain-id}
/// Nonce: ${nonce}
/// Issued At: ${issued-at}
/// Expiration Time: ${expiration-time}
/// Not Before: ${not-before}
/// Request ID: ${request-id}
/// Resources:
/// - ${resources[0]}
/// - ${resources[1]}
/// ...
/// - ${resources[n]}
/// ```
/// Source: [EIP4361](https://eips.ethereum.org/EIPS/eip-4361)
///
#[derive(Deserialize, Serialize, Debug)]
pub struct AuthRequest {
    message: String,
    signature: String,
}

/// An authorization is issued to a particular address based on the fields included in the
/// AuthRequest message. With the Resources vecotr, the API can have even more granular control
/// over the access control of a particular address.
/// All the fields are populated by a AuthRequest.message, from the fields with the same name.
#[derive(Deserialize, Serialize, Debug)]
pub struct Authorization {
    resources: Vec<String>,
    issued_at: String,
    expiration_time: Option<String>,
    not_before: Option<String>,
    pub address: H160,
}

impl Authorization {
    /// Parses a orker::Request for an authentication token, serialized as a JSON object in the
    /// body of the request. The authentication token is used to
    /// retrieve the related Authorization and verify that the token-holder can access the
    /// particular resource.
    pub async fn parse_request(req: &Request) -> Result<String> {
        let headers = req.headers();
        let bearer = headers.get("BEARER")?;
        let cookie = headers.get("AUTH-SIWE")?;
        match bearer.or(cookie) {
            Some(token) => Ok(token),
            None => Err(worker::Error::from("no authorization header found")),
        }
    }
    /// Get an authorizsation from the Cloudflare KV store, based on a token. The token is retrived
    /// from the request with parse_request and used as the key to find the Authorization struct.
    pub async fn get<T>(env: &Env, token: T) -> Result<Option<Authorization>>
    where
        T: Into<String>,
    {
        let store = env.kv("AUTHENTICATION")?;
        store
            .get(&token.into())
            .json::<Authorization>()
            .await
            .map_err(worker::Error::from)
    }
    /// Creates an Authorization in the Cloudflare KC store based on an AuthRequest.
    /// After the message is verified against the signature, the authorization is tied to the
    /// address that signed the message.  The message is converted to bytes and hashed with a
    /// pseudorandomly generated salt. The hash is used as the KEY of the Authorization and
    /// returned to the user to be used as a token.
    ///
    /// For better UX, we return the token in the form of a cookie that can be used by the web
    /// application.
    ///
    /// The Authorization value is set to expire at the Cloduflare KV store at the same time that
    /// it expires as an Authorization, defined in the `expiration_time` field of the
    /// SIWE::Message. That way, we don't have to deal with stale records, but Cloudflare takes
    /// care of it. After it expires, the token will no longer be usable and the user will have to
    /// Authorize again and use a new token.
    ///
    pub async fn create(env: &Env, auth: AuthRequest) -> Result<String> {
        let message: Message =
            Message::from_str(&auth.message).map_err(|err| worker::Error::from(err.to_string()))?;
        match message.verify(
            Signature::from_str(&auth.signature)
                .map_err(|err| worker::Error::from(err.to_string()))?
                .into(),
        ) {
            Ok(_) => {
                let authentication = env.kv("AUTHENTICATION")?;
                let mut rng = rand::thread_rng();
                let mut hasher = Sha256::new();
                let message: Message = Message::from_str(&auth.message)
                    .map_err(|err| worker::Error::from(err.to_string()))?;
                let auth = Authorization {
                    resources: message
                        .resources
                        .iter()
                        .map(|x| x.as_str().to_owned())
                        .collect::<Vec<String>>(),
                    issued_at: format!("{}", message.issued_at),
                    expiration_time: message.expiration_time.clone().map(|x| format!("{}", x)),
                    not_before: message.not_before.map(|x| format!("{}", x)),
                    address: H160(message.address),
                };
                let auth_string: String = serde_json::to_string(&auth).unwrap();
                hasher.update(auth_string.as_bytes());
                // add salt to the auth token
                hasher.update(rng.gen::<[u8; 32]>());
                let hash = format!("{:X}", hasher.finalize());
                authentication
                    .put(&hash, &auth_string)?
                    .expiration(
                        message
                            .expiration_time
                            .unwrap()
                            .as_ref()
                            .timestamp()
                            .unsigned_abs(),
                    )
                    .execute()
                    .await?;
                Ok(hash)
            }
            Err(_) => Err(worker::Error::from(
                "Failed to verify supplied message with signature",
            )),
        }
    }
}
impl AuthRequest {
    /// Parses a worker::Request struct for an AuthRequest struct, serialized as a JSON object in
    /// the body of the request.
    ///
    /// ```no_run
    /// let router = Router::new();
    /// router.post_async("/api/v1/authorize", |req, ctx| async move {
    /// let auth_req: AuthRequest = AuthRequest::from_req(req).await?;
    /// }).run(req, ctx).await
    /// ```
    pub async fn from_req(mut req: Request) -> Result<AuthRequest> {
        let body = req
            .json::<AuthRequest>()
            .await
            .map_err(|error| worker::Error::from(format!("body parsing: {:?}", error)))?;
        let sig: String = body.signature.trim_start_matches("0x").to_owned();
        let msg: String = body.message;
        Ok(AuthRequest {
            message: msg,
            signature: sig,
        })
    }
}
