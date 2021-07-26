//! Default Compute@Edge template program.

use fastly::http::{header, Method, StatusCode};
use fastly::{mime, Error, Request, Response};
use std::net::{IpAddr, Ipv4Addr};
use serde_json;
use serde::Deserialize;
// use std::net::Ipv4Addr;

/// The name of a backend server associated with this service.
///
/// This should be changed to match the name of your own backend. See the the `Hosts` section of
/// the Fastly WASM service UI for more information.
const HTTPBIN_BACKEND: &str = "httpbin";

/// The name of a second backend associated with this service.
const DNS_OVER_HTTPS_BACKEND: &str = "dns_google";

const DNS_OVER_HTTPS_BASE_URL: &str = "https://dns.google/resolve";

const USERAGENT_GOOGLEBOT: &str = "Googlebot";

// Reverse the IPs for the reverse lookup. Equal to the command `dig -x [some IP]`
// For example, `dig -x 66.249.66.1`
// fn reverse_ipv4_lookup(client_ip: IpAddr, record_type: &str) -> Result<Vec<String>, Error>{
fn reverse_ipv4_lookup(mut req: Request) -> Result<Request, Error> {    

    let  client_ip_address: IpAddr = req.get_client_ip_addr().unwrap();

    if client_ip_address.is_ipv4() {
        println!("IP is IPv4");
        let ipv4_address: Ipv4Addr = format!("{}", req.get_client_ip_addr().unwrap()).parse()?;
        let mut ipv4_vec = ipv4_address.octets();
        ipv4_vec.reverse();

        let ipv4_reverse_addr: Ipv4Addr = Ipv4Addr::new(ipv4_vec[0], ipv4_vec[1], ipv4_vec[2], ipv4_vec[3]);
        let hostname_for_reverse_lookup: String = format!("{}{}", &ipv4_reverse_addr.to_string(), ".in-addr.arpa");

        // Test case
        // let hostname_for_reverse_lookup: String = format!("{}{}", "1.66.249.66", ".in-addr.arpa");
        let ipv4_reverse_lookup: Vec<String> = get_dns_record(&hostname_for_reverse_lookup, "PTR")?;

        req.set_header("Fastly-Reverse-Lookup", format!("{:?}", ipv4_reverse_lookup));
    }
    if client_ip_address.is_ipv6() {
        println!("The client IP is IPv6");
    }

    return Ok(req)
}

fn googlebot_check(mut req: Request) -> Result<Request, Error> {
    //check user-agent
    //if user-agent is not valid then say the request is an imposter bot.
    let client_ua = req.get_header_str("user-agent").unwrap();
    if client_ua.contains(USERAGENT_GOOGLEBOT) {
        // println!("user-agent contains Googlebot");
        req = reverse_ipv4_lookup(req)?;
        if req.get_header_str("Fastly-Reverse-Lookup").unwrap().contains("googlebot.com") {
            // If the lookup is valid, then set the header good-bot
            req.set_header("Fastly-Bot", "good-bot");
        } else {
            // If the lookup  is NOT valid, then set the header imposter-bot
            req.set_header("Fastly-Bot", "imposter-bot");
        }
    }

    return Ok(req)
}

// curl 'https://dns.google/resolve?name=www.fastly.comi&type=A'
fn get_dns_record(hostname: &str, record_type: &str) -> Result<Vec<String>, Error> {

    // https://developers.google.com/speed/public-dns/docs/doh/json
    // https://github.com/serde-rs/json/issues/507
    #[allow(non_snake_case)]
    #[derive(Deserialize, Debug)]
    struct GoogleDNSModel {
        Answer: Option<Vec<Answer>>,
        Authority: Option<Vec<Authority>>,
    }
    
    #[allow(non_snake_case)]
    #[derive(Deserialize, Debug)]
    struct Answer {
        name: String,
        data: String,
        TTL: i64,
        r#type: i64,
    }

    #[allow(non_snake_case)]
    #[derive(Deserialize, Debug)]
    struct Authority {
        name: String,
        data: String,
        TTL: i64,
        r#type: i64,
    }

    let resolve_query = format!("name={}&type={}", hostname, record_type);
    println!("[DEBUG] {}?{}", DNS_OVER_HTTPS_BASE_URL, resolve_query);
    let mut dns_over_https_resp = Request::get(DNS_OVER_HTTPS_BASE_URL)
                .with_header("User-Agent", "fastly-rust-C@E")
                .with_query_str(resolve_query)
                .send(DNS_OVER_HTTPS_BACKEND)?;

    let dns_over_https_resp_json: serde_json::Value = dns_over_https_resp.take_body_json::<serde_json::Value>()?;

    println!("dns_over_https_resp_json, {}", dns_over_https_resp_json);

    let dns_over_https_model: GoogleDNSModel = serde_json::from_value(dns_over_https_resp_json)?;
    
    let mut dns_answers = Vec::new();

    // TODO Add a match for when Authority is returned or Answer is returned.
    if dns_over_https_model.Answer.is_none() == false {
        for answer in dns_over_https_model.Answer.unwrap() {
            dns_answers.push(answer.data.parse()?);
            
            // https://en.wikipedia.org/wiki/List_of_DNS_record_types
            if answer.r#type == 1 || answer.r#type == 28 {
                // println!("type={}", answer.r#type);
                dns_answers.push(answer.data.parse()?);
            }
        }
    }

    Ok(dns_answers)
}

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {

    // println!("reverse_ipv4_lookup: {:?}", reverse_ipv4_lookup("66.249.66.1", "PTR")?);
    // println!("reverse_ipv4_lookup: {:?}", reverse_ipv4_lookup(req.get_client_ip_addr().unwrap(), "PTR")?);

    // req = reverse_ipv4_lookup(req)?;

    println!("checking for googlebot");
    req = googlebot_check(req)?;

    // println!("reverse_ipv4_lookup: {:?}", reverse_ipv4_lookup(req)?);

    // println!("req client IP {}", format!("{:?}", ));
    // println!("dns_record_resolution {:?}", dns_record_resolution.unwrap());

    // Make any desired changes to the client request.
    // req.set_header(header::HOST, "dns.google");

    // Filter request methods...
    match req.get_method() {
        // Allow GET and HEAD requests.
        &Method::GET | &Method::HEAD => (),

        // Accept PURGE requests; it does not matter to which backend they are sent.
        // m if m == "PURGE" => return Ok(req.send(BACKEND_NAME)?),

        // Deny anything else.
        _ => {
            return Ok(Response::from_status(StatusCode::METHOD_NOT_ALLOWED)
                .with_header(header::ALLOW, "GET, HEAD")
                .with_body_text_plain("This method is not allowed\n"))
        }
    };

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
            Ok(req.send(HTTPBIN_BACKEND)?)
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
