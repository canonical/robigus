// WP-1.1: these modules were private, which left every `pub` item unreachable
// and failed the clippy `-D warnings` gate. They are public to match the
// library-API direction in spec §15; WP-1.2 refines the public surface.
pub mod dpkg;
pub mod model;
pub mod solver;
