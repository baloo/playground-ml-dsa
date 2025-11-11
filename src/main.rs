use std::{ops::Deref, str::FromStr, time::Duration};

use ml_dsa::{KeyPair, MlDsa87};
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use signature::Keypair;
use x509_cert::{
    SubjectPublicKeyInfo,
    builder::{Builder, CertificateBuilder, profile},
    der::{EncodePem, pem::LineEnding},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};

static PRIVATE_KEY: &str = include_str!("./ML-DSA-87-seed.priv");

fn main() {
    let keypair = KeyPair::<MlDsa87>::from_pkcs8_pem(PRIVATE_KEY).expect("parse private key");

    let pub_key = SubjectPublicKeyInfo::from_key(keypair.verifying_key()).unwrap();

    let serial_number = SerialNumber::generate(&mut rand::thread_rng());
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject = Name::from_str("CN=hi,O=Acme Inc,C=US").unwrap();
    let profile = profile::cabf::Root::new(false, subject).expect("Create root profile");

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate builder");

    let cert = builder.build(&keypair).expect("Create certificate");

    println!(
        "{}",
        keypair.to_pkcs8_pem(LineEnding::default()).unwrap().deref()
    );

    println!("{}", cert.to_pem(LineEnding::default()).unwrap());
}
