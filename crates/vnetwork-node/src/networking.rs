use crate::transport::{P2pSyncRequest, P2pSyncResponse};
use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::{
    autonat, gossipsub, identify, kad, relay, request_response, swarm::NetworkBehaviour,
    StreamProtocol,
};
use std::io;
use std::time::Duration;

#[derive(Debug, Clone, Default)]
pub struct VNetworkSyncCodec;

#[async_trait]
impl request_response::Codec for VNetworkSyncCodec {
    type Protocol = StreamProtocol;
    type Request = P2pSyncRequest;
    type Response = P2pSyncResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed_json(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed_json(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed_json(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed_json(io, &res).await
    }
}

async fn read_length_prefixed_json<T, M>(io: &mut T) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: serde::de::DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "sync message exceeds 16 MiB limit",
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn write_length_prefixed_json<T, M>(io: &mut T, msg: &M) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: serde::Serialize,
{
    let bytes =
        serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
    io.write_all(&len).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

#[derive(NetworkBehaviour)]
pub struct VNetworkBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub sync: request_response::Behaviour<VNetworkSyncCodec>,
    pub relay_client: relay::client::Behaviour,
    pub autonat: autonat::Behaviour,
}

pub fn build_behaviour(
    key: &libp2p::identity::Keypair,
    relay_client: relay::client::Behaviour,
    agent_version: String,
) -> Result<VNetworkBehaviour, Box<dyn std::error::Error + Send + Sync>> {
    let peer_id = libp2p::PeerId::from(key.public());

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_millis(250))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(4 * 1024 * 1024)
        .build()?;
    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )?;

    let identify = identify::Behaviour::new(
        identify::Config::new("/vnetwork/identify/1.0.0".to_string(), key.public())
            .with_agent_version(agent_version),
    );

    let store = kad::store::MemoryStore::new(peer_id);
    let kademlia = kad::Behaviour::new(peer_id, store);

    let sync = request_response::Behaviour::new(
        [(
            StreamProtocol::new("/vnetwork/sync/1.0.0"),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());

    Ok(VNetworkBehaviour {
        gossipsub,
        identify,
        kademlia,
        sync,
        relay_client,
        autonat,
    })
}
