use ironrdp_cliprdr::backend::CliprdrBackendFactory;

use crate::ServerEventSender;

pub trait CliprdrServerFactory: CliprdrBackendFactory + ServerEventSender {
    /// The largest clipboard message the server reassembles from a client, or no limit.
    /// A client that sends a longer one is disconnected, so the limit belongs above the largest answer the backend
    /// takes.
    fn max_message_size(&self) -> Option<usize> {
        None
    }
}
