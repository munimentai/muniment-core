//! Portable supervision for line-oriented child processes.

mod io;
mod jsonrpc;
mod supervisor;

pub use io::{LineReader, LineWriter, SidecarError, SidecarIo};
pub use jsonrpc::{
    JsonRpcCancellationToken, JsonRpcErrorObject, JsonRpcErrorResponse, JsonRpcId,
    JsonRpcNotification, JsonRpcRequest, JsonRpcSuccess, JsonRpcTransport, JsonRpcTransportError,
    JsonRpcVersion,
};
pub use supervisor::{
    RestartPolicy, SidecarConfig, SidecarEvent, SidecarEventCause, SidecarStatus, SidecarSupervisor,
};
