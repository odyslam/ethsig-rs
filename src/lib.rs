use ethers::core::utils::to_checksum;
use ethers::types::{Address, Signature, H160};
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::Response;
use worker::*;
mod utils;
use hex::FromHex;
use rand::Rng;
use sha2::{Digest, Sha256};
use siwe::Message;
use std::str::FromStr;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

#[derive(Deserialize, Serialize)]
struct AuthRequest {
    message: String,
    signature: String,
}

#[derive(Deserialize, Serialize)]
struct Authorization {
    resources: Vec<String>,
    issued_at: String,
    expiration_time: Option<String>,
    not_before: Option<String>,
    address: H160,
}

impl Authorization {
    async fn from_req(env: &Env, req: &Request) -> Result<Option<Authorization>> {
        let headers = req.headers();
        let bearer = headers.get("BEARER")?;
        let cookie = headers.get("AUTH-SIWE")?;
        let token = match bearer.or(cookie) {
            Some(token) => token,
            None => return Err(worker::Error::from("no authorization header found")),
        };
        let store = env.kv("AUTHENTICATION")?;
        store
            .get(&token)
            .json::<Authorization>()
            .await
            .map_err(|error| worker::Error::from(error))
    }
    async fn is_authorized(env: &Env, req: &Request) -> Result<bool> {
        match Authorization::from_req(env, req).await? {
            Some(auth) => Ok(auth.resources.contains(&req.url()?.path().to_string())),
            None => Err(worker::Error::from("could not find auth object")),
        }
    }
}

#[event(fetch, respond_with_errors)]
pub async fn main(req: Request, env: Env, worker_ctx: Context) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let authorized: bool = Authorization::is_authorized(&env, &req).await?;
    let router = Router::new();
    router
        .get("/api/v0/info", |req, _ctx| {
            let version = "0.1";
            console_log!("{}", req.url()?.path());
            Response::ok(version)
        })
        .post_async("/authorize", |mut req, ctx| async move {
            let body = req
                .json::<AuthRequest>()
                .await
                .map_err(|error| worker::Error::from(format!("body parsing: {:?}", error)))?;
            let signature = <[u8; 65]>::from_hex(body.signature.trim_start_matches("0x"))
                .map_err(|error| worker::Error::from(format!("signature parsing: {:?}", error)))?;
            let message: Message = body.message.parse().map_err(|error| {
                worker::Error::from(format!("siwe message parsing: {:?}", error))
            })?;
            match message.verify(signature) {
                Ok(_) => {
                    let authentication = ctx.kv("AUTHENTICATION")?;
                    let mut rng = rand::thread_rng();
                    let mut hasher = Sha256::new();
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
                    // store the auth object of a user with the auth token as key
                    // the auth object KV will expire when then SIWE message expires as well.
                    // That way, we don't have stale auth objects in our KV store
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
                    let mut headers = Headers::new();
                    console_log!(
                        r#"
########
New session:
user: {}
key: {}
value: {}
########
"#,
                        to_checksum(&H160(message.address), Some(0)),
                        &hash,
                        &auth_string
                    );
                    headers.set(
                        "Set-cookie",
                        &format!(
                            "SIWE-AUTH={}; Secure; HttpOnly; SameSite=Lax; Expires={}",
                            &hash,
                            Date::now().to_string()
                        ),
                    )?;
                    let res =
                        Response::redirect(worker::Url::from_str("http:/localhost/").unwrap())
                            .unwrap()
                            .with_headers(headers);
                    return Ok(res);
                }
                Err(error) => {
                    return Response::from_json(&json!(
                        {"verified": false, "error" : format!("{:?}", error) }))
                }
            }
        })
        .get(
            "/api/v0/address/:address/signature/:signature/message/:message",
            |_req, ctx| {
                let message = ctx.param("message").unwrap();
                let signature = Signature::from_str(&ctx.param("signature").unwrap());
                match signature {
                    Ok(sig) => {
                        let address: Address = match ctx.param("address").unwrap().parse() {
                            Ok(addr) => addr,
                            Err(_error) => {
                                return Response::error("Could not parse address", 500);
                            }
                        };
                        let address_ascii = ethers::core::utils::to_checksum(&address, None);
                        let res = format!(
                            r#"
Signature: {:?}
Message: {}
Address: {}
Verified: {:?}
                        "#,
                            signature,
                            message,
                            address_ascii,
                            sig.verify(message.clone(), address)
                        );
                        return Response::ok(res);
                    }
                    Err(error) => {
                        return Response::error(
                            format!("Could not parse signature. Error: {}", error),
                            500,
                        );
                    }
                }
            },
        )
        .run(req, worker_env)
        .await
}
