//! Every fact about providers and models, as data: the providers and how each
//! signs in, the local servers and their ports, the model lists servers and
//! providers report, context windows, output limits and prices. The crate also
//! renders that data into Pi's `models.json`.

pub mod endpoint_models;
pub mod family;
pub mod http;
pub mod local_servers;
pub mod model_catalog;
pub mod provider_models;
pub mod registry;
pub mod window;

#[cfg(test)]
mod test_server;
