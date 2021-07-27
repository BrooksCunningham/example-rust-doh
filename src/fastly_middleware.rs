// use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request, Response};
// use std::net::{IpAddr, Ipv4Addr};
// use serde_json;
// use serde::Deserialize;

// declare the local files that will be used for the middleware
mod fastly_doh;

// Function for manipulating a request.
pub fn middlware_req_handler(mut req: Request) -> Result<Request, Error> {
    
    //TODO allow for a mechanism to enable or disable functionality via edge dictionaries in a similar way as feature flags.
    println!("checking for googlebot");
    req = fastly_doh::googlebot_check(req)?;

    //Add more integrations...
    Ok(req)
}

// Function for manipulating a response.
pub fn middlware_resp_handler(mut resp: Response) -> Result<Response, Error> {
    //TODO allow for a mechanism to enable or disable functionality via edge dictionaries in a similar way as feature flags.
    Ok(resp)
}