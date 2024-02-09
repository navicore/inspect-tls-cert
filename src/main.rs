use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore, ServerName};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use webpki_roots::TLS_SERVER_ROOTS;
use x509_parser::prelude::*;

struct CertificateInfo {
    valid: bool,
    expires: ASN1Time,
    issued_by: String,
}

async fn analyze_tls_certificate(
    domain: &str,
) -> Result<CertificateInfo, Box<dyn std::error::Error>> {
    let addr = format!("{}:443", domain);
    let tcp_stream = TcpStream::connect(addr).await?;

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(domain)?;

    let tls_stream = connector.connect(server_name, tcp_stream).await?;
    let certificates = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or("No certificates found")?;

    let certificate = certificates.first().ok_or("No certificates found")?;
    let parsed_cert = &certificate.0; // DER-encoded certificate

    // Parse the DER-encoded certificate using `x509-parser`
    let (_, cert) =
        parse_x509_certificate(parsed_cert).map_err(|_| "Failed to parse certificate")?;

    //let issuer = cert.issuer();
    let validity = cert.validity();
    let not_after = validity.not_after;
    let valid = validity.is_valid();

    // Placeholder for demonstration: Extracting certificate info directly is non-trivial and requires parsing
    let expires = not_after;

    use der_parser::oid::Oid;
    use x509_parser::prelude::*;

    // Ensure you have these OIDs properly defined; for example:
    let oid_cn = Oid::from(&[2, 5, 4, 3]).unwrap(); // Common Name
    let oid_o = Oid::from(&[2, 5, 4, 10]).unwrap(); // Organization
                                                    // Add other OIDs as necessary...

    // Inside your analyze_tls_certificate function, after parsing the certificate:
    let issuer = cert.tbs_certificate.issuer;
    let mut issued_by_parts = Vec::new();

    for rdn in issuer.iter() {
        for attr in rdn.iter() {
            let attr_oid = attr.attr_type();
            let value = attr.attr_value();

            // Convert OID to a readable string, if known
            let attr_type_string = if *attr_oid == oid_cn {
                "CN"
            } else if *attr_oid == oid_o {
                "O"
            }
            // Add additional comparisons for other known OIDs
            else {
                "_"
            };

            if attr_type_string == "_" {
                continue;
            };

            // Inside your loop where you iterate over the attributes

            let attr_value_string = match value.as_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    // If direct conversion fails, try interpreting the bytes as UTF-8
                    if let Ok(utf8_value) = std::str::from_utf8(value.data) {
                        utf8_value.to_string()
                    } else {
                        // Fallback if UTF-8 conversion also fails
                        format!("{:?}", value.data)
                    }
                }
            };

            if attr_value_string != "" {
                let formatted = format!("{}: {}", attr_type_string, attr_value_string);
                issued_by_parts.push(formatted);
            }
        }
    }

    let issued_by = issued_by_parts.join(", ");
    let certificate_info = CertificateInfo {
        valid,   // Assuming the certificate is valid if the handshake was successful.
        expires, // Placeholder for actual expiry date
        issued_by: issued_by.to_string(), // Placeholder for actual issuer
    };

    Ok(certificate_info)
}

#[tokio::main]
async fn main() {
    //let domain = "example.com";
    let domain = "www.vw.com";
    match analyze_tls_certificate(domain).await {
        Ok(info) => {
            println!(
                "Certificate Info: Valid: {}, Expires: {:?}, Issued by: {}",
                info.valid, info.expires, info.issued_by
            );
        }
        Err(e) => println!("Error retrieving certificate: {}", e),
    }
}
