pub mod mermaid;
pub mod plugin;
pub mod prism;

use std::collections::HashMap;

pub fn new<'r>(plugins: Vec<Box<dyn plugin::Plugin<'r>>>) -> plugin::PluginManager<'r> {
    let base_static_resources = load_static_resources!(
    "/static/index.html" => "../static/index.html",
    "/static/custom.js" => "../static/custom.js",
    "/static/custom.css" => "../static/custom.css",
    "/static/favicon.ico" => "../static/favicon.ico"
    );

    let base_css_imports = vec![
        concat!("/static/custom.css?v", env!("CARGO_PKG_VERSION")),
    ];

    let base_js_imports = vec![
        concat!("/static/custom.js?v", env!("CARGO_PKG_VERSION")),
    ];

    plugin::PluginManager::build()
        .plugins(plugins)
        .static_resources(base_static_resources)
        .css_imports(base_css_imports)
        .js_imports(base_js_imports)
        .finalize()
}
