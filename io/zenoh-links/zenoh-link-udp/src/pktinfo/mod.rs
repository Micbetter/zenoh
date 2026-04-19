//
// Copyright (c) 2025 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

#[cfg(target_family = "unix")]
mod pktinfo_unix;
use std::{io, net::SocketAddr, sync::Arc};

#[cfg(target_family = "unix")]
use pktinfo_unix::*;

#[cfg(target_family = "windows")]
mod pktinfo_windows;
#[cfg(target_family = "windows")]
use pktinfo_windows::*;

#[cfg(all(not(target_family = "windows"), not(target_family = "unix")))]
mod pktinfo_generic;
#[cfg(all(not(target_family = "windows"), not(target_family = "unix")))]
use pktinfo_generic::*;
use tokio::net::UdpSocket;

#[derive(Clone)]
pub(crate) struct PktInfoUdpSocket {
    pub(crate) socket: Arc<UdpSocket>,
    pktinfo_retrieval_data: PktInfoRetrievalData,
    local_address: SocketAddr,
}

impl PktInfoUdpSocket {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> io::Result<PktInfoUdpSocket> {
        let pktinfo_retrieval_data = enable_pktinfo(&socket)?;
        let local_address = socket.local_addr()?;
        Ok(PktInfoUdpSocket {
            socket,
            pktinfo_retrieval_data,
            local_address,
        })
    }

    pub(crate) async fn receive(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        let res = recv_with_dst(&self.socket, &self.pktinfo_retrieval_data, buffer).await?;

        let mut src_addr = self.local_address;
        if src_addr.ip().is_unspecified() {
            if let Some(addr) = res.2 {
                src_addr = addr;
            }
        }
        Ok((res.0, res.1, src_addr))
    }

    pub(crate) async fn send_to(
        &self,
        buffer: &[u8],
        dst_addr: &SocketAddr,
        src_addr: &SocketAddr,
    ) -> io::Result<usize> {
        #[cfg(target_family = "unix")]
        {
            send_with_src(&self.socket, buffer, dst_addr, src_addr).await
        }
        #[cfg(not(target_family = "unix"))]
        {
            // Fallback for non-unix platforms
            let _ = src_addr;
            self.socket.send_to(buffer, dst_addr).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use tokio::net::UdpSocket;

    use super::*;

    #[tokio::test]
    async fn test_pktinfo_source_ip_consistency() {
        let server_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let server_pktinfo = PktInfoUdpSocket::new(Arc::new(server_socket)).unwrap();

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_target_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_addr.port());

        client_socket.connect(client_target_addr).await.unwrap();

        client_socket.send(b"request").await.unwrap();

        let mut buf = [0u8; 1024];
        let (size, client_addr, captured_local_ip) =
            server_pktinfo.receive(&mut buf).await.unwrap();
        assert_eq!(&buf[..size], b"request");
        assert_eq!(
            captured_local_ip.ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );

        server_pktinfo
            .send_to(b"response", &client_addr, &captured_local_ip)
            .await
            .unwrap();

        let mut resp_buf = [0u8; 1024];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), client_socket.recv(&mut resp_buf))
            .await
            .expect("Timeout: Client did not receive the response. This usually means the source IP drifted and the packet was dropped by the OS kernel.")
            .unwrap();

        assert_eq!(&resp_buf[..n], b"response");
    }

    const AUXILIARY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

    async fn try_bind_auxiliary_ip() -> Option<UdpSocket> {
        UdpSocket::bind(SocketAddr::new(AUXILIARY_IP, 0)).await.ok()
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_source_ip_drifts_without_pktinfo_send() {
        if try_bind_auxiliary_ip().await.is_none() {
            eprintln!(
                "Skipping test: {} not available. \
                 To run locally: sudo ip link add zenoh_test0 type dummy && \
                 sudo ip addr add 198.51.100.1/24 dev zenoh_test0 && \
                 sudo ip link set zenoh_test0 up",
                AUXILIARY_IP
            );
            return;
        }

        let server_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let server_port = server_socket.local_addr().unwrap().port();

        let client_socket = UdpSocket::bind(SocketAddr::new(AUXILIARY_IP, 0))
            .await
            .unwrap();
        client_socket
            .connect(SocketAddr::new(AUXILIARY_IP, server_port))
            .await
            .unwrap();

        client_socket.send(b"ping").await.unwrap();

        let mut buf = [0u8; 1024];
        let (_, client_addr) = server_socket.recv_from(&mut buf).await.unwrap();

        server_socket.send_to(b"pong", &client_addr).await.unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client_socket.recv(&mut buf),
        )
        .await;

        assert!(
            result.is_err(),
            "Expected timeout due to source IP drift, but client received the reply. \
             The kernel picked the correct source IP by chance or the bug is not reproducible \
             in this environment."
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_pktinfo_send_prevents_source_ip_drift() {
        if try_bind_auxiliary_ip().await.is_none() {
            eprintln!(
                "Skipping test: {} not available. \
                 To run locally: sudo ip link add zenoh_test0 type dummy && \
                 sudo ip addr add 198.51.100.1/24 dev zenoh_test0 && \
                 sudo ip link set zenoh_test0 up",
                AUXILIARY_IP
            );
            return;
        }

        let server_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let server_port = server_socket.local_addr().unwrap().port();
        let server_pktinfo = PktInfoUdpSocket::new(Arc::new(server_socket)).unwrap();

        let client_socket = UdpSocket::bind(SocketAddr::new(AUXILIARY_IP, 0))
            .await
            .unwrap();
        client_socket
            .connect(SocketAddr::new(AUXILIARY_IP, server_port))
            .await
            .unwrap();

        client_socket.send(b"ping").await.unwrap();

        let mut buf = [0u8; 1024];
        let (size, client_addr, captured_local_ip) =
            server_pktinfo.receive(&mut buf).await.unwrap();
        assert_eq!(&buf[..size], b"ping");
        assert_eq!(captured_local_ip.ip(), AUXILIARY_IP);

        server_pktinfo
            .send_to(b"pong", &client_addr, &captured_local_ip)
            .await
            .unwrap();

        let mut resp_buf = [0u8; 1024];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            client_socket.recv(&mut resp_buf),
        )
        .await
        .expect(
            "Timeout: source IP drifted despite IP_PKTINFO send. \
             The fix is not working correctly.",
        )
        .unwrap();

        assert_eq!(&resp_buf[..n], b"pong");
    }
}
