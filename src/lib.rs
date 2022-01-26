use ethers::core::utils::to_checksum;
use ethers::types::{Address, Signature};
use worker::*;
mod utils;
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
