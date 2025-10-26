//!
//! MIT License
//!
//! Copyright (c) 2020 Devolutions/IronRDP
//!
//! Permission is hereby granted, free of charge, to any person obtaining a copy
//! of this software and associated documentation files (the "Software"), to deal
//! in the Software without restriction, including without limitation the rights
//! to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//! copies of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//! AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//! SOFTWARE.
//!
//! This file was adapted from:
//! <https://github.com/Devolutions/IronRDP/blob/ac291423de6835df855e1b40c8da6b45ac0905d9/crates/ironrdp-tokio/src/reqwest.rs>
//!
//!
//! Modified by Aviv Naaman @AvivNaaman on 2025-08-08
//! This module is async-only, since [sspi] implements a synchronous network client.

use url::Url;

use sspi::NetworkRequest;
use sspi::network_client::*;
use sspi::{Error, ErrorKind, Result};

#[cfg(feature = "async")]
mod client_impl {
    use core::future::Future;
    use core::net::{IpAddr, Ipv4Addr};
    use core::pin::Pin;

    use super::*;
    use futures_util::TryFutureExt;
    use reqwest::Client;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpStream, UdpSocket};

    pub struct ReqwestNetworkClient(Ipv4Addr);

    impl AsyncNetworkClient for ReqwestNetworkClient {
        fn send<'a>(
            &'a mut self,
            network_request: &'a NetworkRequest,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>> {
            Box::pin(ReqwestNetworkClient::send(self, network_request))
        }
    }

    impl ReqwestNetworkClient {
        pub fn new(server_address: Ipv4Addr) -> Self {
            Self(server_address)
        }
    }

    impl ReqwestNetworkClient {
        pub async fn send<'a>(&'a mut self, request: &'a NetworkRequest) -> Result<Vec<u8>> {
            log::debug!("Sending SSPI network request to {} using protocol {:?}", request.url, request.protocol);
            log::debug!("Request data length: {} bytes", request.data.len());
            
            let result = match &request.protocol {
                NetworkProtocol::Tcp => {
                    log::debug!("Using TCP protocol for request");
                    self.send_tcp(&request.url, &request.data).await
                },
                NetworkProtocol::Udp => {
                    log::debug!("Using UDP protocol for request");
                    self.send_udp(&request.url, &request.data).await
                },
                NetworkProtocol::Http | NetworkProtocol::Https => {
                    log::debug!("Using HTTP/HTTPS protocol for request");
                    self.send_http(&request.url, &request.data).await
                }
            };
            
            match &result {
                Ok(response) => log::debug!("SSPI network request completed successfully, response length: {} bytes", response.len()),
                Err(e) => log::debug!("SSPI network request failed: {:?}", e),
            }
            
            result
        }

        async fn send_tcp(&self, url: &Url, data: &[u8]) -> sspi::Result<Vec<u8>> {
            let addr = format!(
                "{}:{}",
                self.0.to_string(),
                url.port().unwrap_or(88)
            );
            log::debug!("TCP: Connecting to address: {}", addr);
            
            let mut stream = TcpStream::connect(&addr).await.map_err(|e| {
                log::debug!("TCP: Failed to connect to {}: {:?}", addr, e);
                Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
            })?;
            log::debug!("TCP: Successfully connected to {}", addr);

            log::debug!("TCP: Sending {} bytes of data", data.len());
            stream
                .write(data)
                .map_err(|e| {
                    log::debug!("TCP: Failed to write data: {:?}", e);
                    Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
                })
                .await?;
            log::debug!("TCP: Data sent successfully");

            log::debug!("TCP: Reading response length");
            let len = stream.read_u32().await.map_err(|e| {
                log::debug!("TCP: Failed to read response length: {:?}", e);
                Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
            })?;
            log::debug!("TCP: Response length: {} bytes", len);

            let mut buf = vec![0; len as usize + 4];
            buf[0..4].copy_from_slice(&(len.to_be_bytes()));

            log::debug!("TCP: Reading response data ({} bytes)", len);
            stream
                .read_exact(&mut buf[4..])
                .map_err(|e| {
                    log::debug!("TCP: Failed to read response data: {:?}", e);
                    Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
                })
                .await?;
            log::debug!("TCP: Successfully received {} bytes total", buf.len());

            Ok(buf)
        }

        async fn send_udp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            log::debug!("UDP: Binding to localhost");
            let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .map_err(|e| {
                    log::debug!("UDP: Failed to bind socket: {:?}", e);
                    Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}"))
                })?;
            log::debug!("UDP: Socket bound successfully");

            let addr = format!(
                "{}:{}",
                self.0.to_string(),
                url.port().unwrap_or(88)
            );
            log::debug!("UDP: Sending {} bytes to {}", data.len(), addr);

            udp_socket
                .send_to(data, &addr)
                .await
                .map_err(|e| {
                    log::debug!("UDP: Failed to send data to {}: {:?}", addr, e);
                    Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}"))
                })?;
            log::debug!("UDP: Data sent successfully to {}", addr);

            // 48 000 bytes: default maximum token len in Windows
            let mut buf = vec![0; 0xbb80];
            log::debug!("UDP: Waiting for response (buffer size: {} bytes)", buf.len());

            let n = udp_socket
                .recv(&mut buf)
                .await
                .map_err(|e| {
                    log::debug!("UDP: Failed to receive response: {:?}", e);
                    Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}"))
                })?;
            log::debug!("UDP: Received {} bytes", n);
            let buf = &buf[0..n];

            let mut reply_buf = Vec::with_capacity(n + 4);
            let n = u32::try_from(n)
                .map_err(|e| {
                    log::debug!("UDP: Failed to convert response length: {:?}", e);
                    Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{e:?}"))
                })?;
            reply_buf.extend_from_slice(&n.to_be_bytes());
            reply_buf.extend_from_slice(buf);
            log::debug!("UDP: Prepared response buffer with {} bytes total", reply_buf.len());

            Ok(reply_buf)
        }

        async fn send_http(&mut self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            log::debug!("HTTP: Creating HTTP client");
            let client = Client::new();

            log::debug!("HTTP: Sending POST request to {} with {} bytes", url, data.len());
            let response = client
                .post(url.clone())
                .body(data.to_vec())
                .send()
                .await
                .map_err(|e| {
                    log::debug!("HTTP: Failed to send request to {}: {:?}", url, e);
                    Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!("failed to send KDC request over proxy: {e:?}"),
                    )
                })?;
            log::debug!("HTTP: Received response with status: {}", response.status());
            
            let response = response.error_for_status()
                .map_err(|e| {
                    log::debug!("HTTP: Response status error: {:?}", e);
                    Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!("KdcProxy: {e:?}"),
                    )
                })?;

            log::debug!("HTTP: Reading response body");
            let body = response.bytes().await.map_err(|e| {
                log::debug!("HTTP: Failed to read response body: {:?}", e);
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!("failed to receive KDC response: {e:?}"),
                )
            })?;

            // The type bytes::Bytes has a special From implementation for Vec<u8>.
            let body = Vec::from(body);
            log::debug!("HTTP: Successfully received {} bytes in response body", body.len());

            Ok(body)
        }
    }
}

#[cfg(not(feature = "async"))]
mod client_impl {
    use super::*;
    use byteorder::{BigEndian, ReadBytesExt};
    use reqwest::blocking::Client;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket};

    #[derive(Clone, Default)]
    pub struct ReqwestNetworkClient(Ipv4Addr);

    impl ReqwestNetworkClient {
        pub fn new(server_address: Ipv4Addr) -> Self {
            Self(server_address)
        }
        fn send_tcp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            let addr = format!(
                "{}:{}",
                self.0.to_string(),
                url.port().unwrap_or(88)
            );
            log::debug!("TCP: Connecting to address: {}", addr);
            
            let mut stream = TcpStream::connect(&addr).map_err(|e| {
                log::debug!("TCP: Failed to connect to {}: {:?}", addr, e);
                Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
            })?;
            log::debug!("TCP: Successfully connected to {}", addr);

            log::debug!("TCP: Sending {} bytes of data", data.len());
            stream.write(data).map_err(|e| {
                log::debug!("TCP: Failed to write data: {:?}", e);
                Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
            })?;
            log::debug!("TCP: Data sent successfully");

            log::debug!("TCP: Reading response length");
            let len = stream.read_u32::<BigEndian>().map_err(|e| {
                log::debug!("TCP: Failed to read response length: {:?}", e);
                Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
            })?;
            log::debug!("TCP: Response length: {} bytes", len);

            let mut buf = vec![0; len as usize + 4];
            buf[0..4].copy_from_slice(&(len.to_be_bytes()));

            log::debug!("TCP: Reading response data ({} bytes)", len);
            stream.read_exact(&mut buf[4..]).map_err(|e| {
                log::debug!("TCP: Failed to read response data: {:?}", e);
                Error::new(ErrorKind::NoAuthenticatingAuthority, format!("{:?}", e))
            })?;
            log::debug!("TCP: Successfully received {} bytes total", buf.len());

            Ok(buf)
        }

        fn send_udp(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            log::debug!("UDP: Binding to localhost");
            let udp_socket = UdpSocket::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).map_err(|e| {
                log::debug!("UDP: Failed to bind socket: {:?}", e);
                e
            })?;
            log::debug!("UDP: Socket bound successfully");

            let addr = format!(
                "{}:{}",
                self.0.to_string(),
                url.port().unwrap_or(88)
            );
            log::debug!("UDP: Sending {} bytes to {}", data.len(), addr);
            
            udp_socket.send_to(data, &addr).map_err(|e| {
                log::debug!("UDP: Failed to send data to {}: {:?}", addr, e);
                e
            })?;
            log::debug!("UDP: Data sent successfully to {}", addr);

            // 48 000 bytes: default maximum token len in Windows
            let mut buf = vec![0; 0xbb80];
            log::debug!("UDP: Waiting for response (buffer size: {} bytes)", buf.len());

            let n = udp_socket.recv(&mut buf).map_err(|e| {
                log::debug!("UDP: Failed to receive response: {:?}", e);
                e
            })?;
            log::debug!("UDP: Received {} bytes", n);

            let mut reply_buf = Vec::with_capacity(n + 4);
            reply_buf.extend_from_slice(&(n as u32).to_be_bytes());
            reply_buf.extend_from_slice(&buf[0..n]);
            log::debug!("UDP: Prepared response buffer with {} bytes total", reply_buf.len());

            Ok(reply_buf)
        }

        fn send_http(&self, url: &Url, data: &[u8]) -> Result<Vec<u8>> {
            log::debug!("HTTP: Creating HTTP client");
            let client = Client::new();

            log::debug!("HTTP: Sending POST request to {} with {} bytes", url, data.len());
            let response = client
                .post(url.clone())
                .body(data.to_vec())
                .send()
                .map_err(|err| {
                    log::debug!("HTTP: Failed to send request to {}: {:?}", url, err);
                    match err {
                        err if err.to_string().to_lowercase().contains("certificate") => Error::new(
                            ErrorKind::CertificateUnknown,
                            format!("Invalid certificate data: {:?}", err),
                        ),
                        _ => Error::new(
                            ErrorKind::NoAuthenticatingAuthority,
                            format!("Unable to send the data to the KDC Proxy: {:?}", err),
                        ),
                    }
                })?;
            log::debug!("HTTP: Received response with status: {}", response.status());
            
            let response = response.error_for_status()
                .map_err(|err| {
                    log::debug!("HTTP: Response status error: {:?}", err);
                    Error::new(
                        ErrorKind::NoAuthenticatingAuthority,
                        format!("KDC Proxy: {err}"),
                    )
                })?;

            log::debug!("HTTP: Reading response body");
            let body = response.bytes().map_err(|err| {
                log::debug!("HTTP: Failed to read response body: {:?}", err);
                Error::new(
                    ErrorKind::NoAuthenticatingAuthority,
                    format!(
                        "Unable to read the response data from the KDC Proxy: {:?}",
                        err
                    ),
                )
            })?;

            // The type bytes::Bytes has a special From implementation for Vec<u8>.
            let body = Vec::from(body);
            log::debug!("HTTP: Successfully received {} bytes in response body", body.len());

            Ok(body)
        }
    }

    impl NetworkClient for ReqwestNetworkClient {
        fn send(&self, request: &NetworkRequest) -> Result<Vec<u8>> {
            log::debug!("Sending SSPI network request to {} using protocol {:?}", request.url, request.protocol);
            log::debug!("Request data length: {} bytes", request.data.len());
            
            let result = match request.protocol {
                NetworkProtocol::Tcp => {
                    log::debug!("Using TCP protocol for request");
                    self.send_tcp(&request.url, &request.data)
                },
                NetworkProtocol::Udp => {
                    log::debug!("Using UDP protocol for request");
                    self.send_udp(&request.url, &request.data)
                },
                NetworkProtocol::Http | NetworkProtocol::Https => {
                    log::debug!("Using HTTP/HTTPS protocol for request");
                    self.send_http(&request.url, &request.data)
                }
            };
            
            match &result {
                Ok(response) => log::debug!("SSPI network request completed successfully, response length: {} bytes", response.len()),
                Err(e) => log::debug!("SSPI network request failed: {:?}", e),
            }
            
            result
        }
    }
}

pub use client_impl::*;
