//! Default Compute@Edge template program.

use fastly::http::{StatusCode};
use fastly::{mime, Error, Request, Response};
// use std::net::{IpAddr, Ipv4Addr};
// use serde_json;
// use serde::Deserialize;

mod fastly_middleware;

/// The name of a backend server associated with this service.
///
/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
const HTTPBIN_BACKEND: &str = "httpbin";

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    
    req = fastly_middleware::middlware_req_handler(req)?;

    // Pattern match on the path.
    match req.get_path() {
        // If request is to the `/` path, send a default response.
        "/" => {
            
        Ok(Response::from_status(StatusCode::OK)
            .with_content_type(mime::TEXT_HTML_UTF_8)
            .with_body("<iframe src='https://developer.fastly.com/compute-welcome' style='border:0; position: absolute; top: 0; left: 0; width: 100%; height: 100%'></iframe>\n"))

        }
        // If request is to the `/backend` path, send to a named backend.
        "/anything" => {
            // Request handling logic could go here...  E.g., send the request to an origin backend
            // and then cache the response for one minute.
            // req.set_ttl(60);
            let mut resp = req.send(HTTPBIN_BACKEND)?;
            resp = fastly_middleware::middlware_resp_handler(resp)?;
            Ok(resp)
        }

        // // If request is to a path starting with `/other/`...
        // path if path.starts_with("/other/") => {
        //     // Send request to a different backend and don't cache response.
        //     req.set_pass(true);
        //     Ok(req.send(BACKEND_NAME)?)
        // }

        // Catch all other requests and return a 404.
        _ => Ok(Response::from_status(StatusCode::NOT_FOUND)
            .with_body_text_plain("The page you requested could not be found\n")),
    }
}
