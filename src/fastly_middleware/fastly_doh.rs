// use fastly::http::{header, Method, StatusCode};
use fastly::{Error, Request};
use std::net::{IpAddr, Ipv4Addr};
use serde_json;
use serde::Deserialize;

const DNS_OVER_HTTPS_BACKEND: &str = "dns_google";

const DNS_OVER_HTTPS_BASE_URL: &str = "https://dns.google/resolve";

const USERAGENT_GOOGLEBOT: &str = "Googlebot";

// Reverse the IPs for the reverse lookup. Equal to the command `dig -x [some IP]`
// For example, `dig -x 66.249.66.1`
// fn reverse_ipv4_lookup(client_ip: IpAddr, record_type: &str) -> Result<Vec<String>, Error>{
pub fn reverse_ipv4_lookup(mut req: Request) -> Result<Request, Error> {    

    let client_ip_address: IpAddr = req.get_client_ip_addr().unwrap();

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

pub fn googlebot_check(mut req: Request) -> Result<Request, Error> {
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
pub fn get_dns_record(hostname: &str, record_type: &str) -> Result<Vec<String>, Error> {

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
