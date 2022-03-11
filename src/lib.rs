use ethers::types::Address;
use worker::Response;
use worker::*;
mod utils;
use auth::{AuthRequest, Authorization};
use std::str::FromStr;
mod auth;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or_else(|| "unknown region".into())
    );
}

/// Checks if the request has an authorization token and if that oken is authorized to access
/// the particular resource. Although complex schemes can be used with the Authorization.resources
/// vector, currently we don't use that.
///
/// The authorization scheme is very simple:
///
/// A token that is tied to an Address A, has root access to all resources under `/api/v1/users/A`.
/// For example, they can create a new workstream, edit an old one or delete, because the
/// `workstreams` resource is under the following path: `/api/v1/users/A/workstreams/`.
async fn is_authorized(req: &Request, env: &Env, ctx: &RouteContext<()>) -> Result<bool> {
    let token = auth::Authorization::parse_request(req).await?;
    let auth = match auth::Authorization::get(env, token).await? {
        Some(authorization) => authorization,
        None => return Ok(false),
    };
    let addr = Address::from_str(ctx.param("user").unwrap())
        .map_err(|_| worker::Error::from("Cannot parse address"))?;
    console_log!("Authorization is tied with user: {}", addr);
    Ok(addr == auth.address)
}
/// ## /api/v1/authorize
///
/// HTTP Methods: POST
///
/// Required Authorization: None
///
/// It authorizes an ethereum address to the API and generates a token that is returned to the
/// user. Using that token, the user can access all the resources that have to do with that
/// particular ethereum address (/users/:user/..).
///
/// It accepts an AuthRequest object as a JSON encoded object in the body of the request.
///
/// The message and signature **must** comform to EIP4361: https://eips.ethereum.org/EIPS/eip-4361
///
/// The can be easily generated using:
/// - [siwe-js](https://github.com/spruceid/siwe)
/// - [siwe-rs](https://github.com/spruceid/siwe-rs)
///
/// A succesful response will include the following cookie in the headers: `SIWE-AUH=XXXXXX`,
/// where XXXXX is the authorization token.
///
/// With that token, the user can authorize a request to access a resource via a method that
/// requires authorization. The token expires automatically based on the AuthRequest object that
/// was sent and must be renewed using the same mechanism.
///
/// An example flow of the API:
///
///     ┌───┐                                                        ┌───┐                 ┌───────────────────┐
///     │Bob│                                                        │API│                 │Cloudflare_KV_Store│
///     └─┬─┘                                                        └─┬─┘                 └─────────┬─────────┘
///       │POST /api/v1/authorization, {sig: "0x..", messsage: "{..}"} │                             │          
///       │───────────────────────────────────────────────────────────>│                             │          
///       │                                                            │                             │          
///       │                                                            ────┐                         │          
///       │                                                                │ AuthRequest::parse_req()│          
///       │                                                            <───┘                         │          
///       │                                                            │                             │          
///       │                                                            ────┐                         │          
///       │                                                                │ Authorization::create() │          
///       │                                                            <───┘                         │          
///       │                                                            │                             │          
///       │                                                            │   PUT Authorization {..}    │          
///       │                                                            │────────────────────────────>│          
///       │                                                            │                             │          
///       │                                                            │            Ok()             │          
///       │                                                            │<────────────────────────────│          
///       │                                                            │                             │          
///       │  RESPONSE HEADERS: "set-cookie"="AUTH-SIWE": "xgh934j.."   │                             │          
///       │<───────────────────────────────────────────────────────────│                             │          
///       │                                                            │                             │          
///       │    GET api/v1/authorized_resource, AUTH-SIWE="xgh934j"     │                             │          
///       │───────────────────────────────────────────────────────────>│                             │          
///       │                                                            │                             │          
///       │                                                            │     GET Authorization       │          
///       │                                                            │────────────────────────────>│          
///       │                                                            │                             │          
///       │                                                            │     Authorization {..}      │          
///       │                                                            │<────────────────────────────│          
///       │                                                            │                             │          
///       │                  RESPONSE "authorized!"                    │                             │          
///       │<───────────────────────────────────────────────────────────│                             │          
///     ┌─┴─┐                                                        ┌─┴─┐                 ┌─────────┴─────────┐
///     │Bob│                                                        │API│                 │Cloudflare_KV_Store│
///     └───┘                                                        └───┘                 └───────────────────┘
/// AuthRequest serialized in JSON:
///
/// ```
/// '{\n    \"signature\": \"0x49a6e2a1995fde3bd10bd9ae2ecefe199ecfcb576125cc8582ee8458a4efd62668539b11f7bdb10e07f94b223f266cdd5ed592b37db4a2941541336a696d820a1c\",\n    \"message\": \"localhost:4361 wants you to sign in with your Ethereum account:\\n0xDFA1fEa9915EF18b1f2A752343b168cA9c9d97aB\\n\\nSIWE Notepad Example\\n\\nURI: http://localhost:4361\\nVersion: 1\\nChain ID: 1\\nNonce: zPPtgK5pMVHnnr8Co\\nIssued At: 2022-03-02T10:56:48.478Z\\nExpiration Time: 2022-03-02T20:56:48.474Z\\nResources:\\n- http://localhost:4361/address/0xDFA1fEa9915EF18b1f2A752343b168cA9c9d97aB\"\n}'
/// ```
///
/// If the authorization is succesful, the response will have the following header where the
/// `SIWE-AUTH` cookie is the authorization token.
///
/// ```
/// "set-cookie": "SIWE-AUTH=EACB9E10D0FD122CF0D2BA5F282CEBA0D71B48DD40A04893AAB94D1BE3F16F7D;
/// Secure; HttpOnly; SameSite=Lax; Expires=Tue Mar 08 2022 20:51:45 GMT+0000 (Coordinated
/// Universal Time)"
/// ```
///
///
///
///
#[event(fetch, respond_with_errors)]
pub async fn main(req: Request, env: Env, _worker_ctx: Context) -> Result<Response> {
    log_request(&req);
    utils::set_panic_hook();
    let router = Router::new();
    router
        .get("/api/v0/info", |req, _ctx| {
            let version = "0.1";
            console_log!("{}", req.url()?.path());
            Response::ok(version)
        })
        .post_async("/api/v1/authorize", |req, ctx| async move {
            let auth_req: AuthRequest = AuthRequest::from_req(req).await?;
            let token: String = Authorization::create(&ctx.env, auth_req).await?;
            let mut headers = Headers::new();
            headers.set(
                "Set-cookie",
                &format!(
                    "SIWE-AUTH={}; Secure; HttpOnly; SameSite=Lax; Expires={}",
                    &token,
                    Date::now().to_string()
                ),
            )?;
            let res = Response::ok("authorization created")
                .unwrap()
                .with_headers(headers);
            Ok(res)
        })
        .get_async("/api/v1/authorized_resource", |req, ctx| async move {
            if !is_authorized(&req, &ctx.env, &ctx).await? {
                return Response::error("Unauthorized", 401);
            }
            Response::ok("Authorized!")
        })
        .run(req, env)
        .await
}
