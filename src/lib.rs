use ethers::core::utils::to_checksum;
use ethers::types::{Address, Signature};
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::*;
mod utils;
use hex::FromHex;
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
struct Authentication {
    message: String,
    signature: String,
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let router = Router::new();
    router
        .get("/api/v0/info", |_, _ctx| {
            let version = "0.1";
            Response::ok(version)
        })
        .post_async("/authenticate", |mut req, _ctx| async move {
            let body = match req.json::<Authentication>().await {
                Ok(json) => json,
                Err(error) => return Response::error(format!("Body Parsing:{:?}", error), 500),
            };
            let signature = match <[u8; 65]>::from_hex(body.signature) {
                Ok(sig) => sig,
                Err(error) => {
                    return Response::error(format!("Signature Parsing: {:?}", error), 500)
                }
            };
            let message: Message = match body.message.parse() {
                Ok(msg) => msg,
                Err(error) => return Response::error(format!("Message Parsing:{:?}", error), 500),
            };
            match message.verify(signature) {
                Ok(signer) => return Response::from_json(&json!({ "status": signer })),
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
        .run(req, env)
        .await
}
