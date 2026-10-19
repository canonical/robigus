//! Additional integration tests covering dump, unmet, and filter operations.

use rapt::RaptQuery;
use rapt::models::{
    BinaryPackage, DependencyClause, DependencyGroup, DependencyItem, DependencyType,
    PackageOrigin, ProvideItem, SeriesCache,
};
use rapt::types::{Architecture, Component, PackageTarget, Pocket, QueryFilter};

fn make_pkg(
    name: &str,
    version: &str,
    pocket: Pocket,
    component: Component,
    arch: Architecture,
    deps: Vec<(DependencyType, &str)>,
    provides: Vec<&str>,
) -> BinaryPackage {
    let origin = PackageOrigin::new(
        pocket,
        component,
        arch,
        "http://archive.ubuntu.com/ubuntu",
        format!("resolute{}", pocket.suite_suffix()),
    );

    let mut dep_groups = Vec::new();
    for (dep_type, dep_name) in deps {
        let item = DependencyItem::new(dep_name, None::<String>, None::<String>, None::<String>);
        dep_groups.push(DependencyGroup::new(
            dep_type,
            vec![DependencyClause::new(vec![item])],
        ));
    }

    let prov_items: Vec<ProvideItem> = provides
        .into_iter()
        .map(|p| ProvideItem::new(p, None::<String>))
        .collect();

    BinaryPackage::new(
        name,
        version,
        arch.as_str(),
        Some("Maintainer <maintainer@example.com>"),
        Some("200"),
        dep_groups,
        prov_items,
        Some("net"),
        Some("optional"),
        Some("https://example.com"),
        Some(format!("{name} - description")),
        Some("md5hash123"),
        Some(format!("pool/main/{name}.deb")),
        Some(1000),
        Some("md5"),
        Some("sha1"),
        Some("sha256"),
        Some("sha512"),
        None::<String>,
        origin,
        vec![
            ("Package".to_string(), name.to_string()),
            ("Version".to_string(), version.to_string()),
        ],
    )
}

#[test]
fn test_unmet_and_dump() {
    let mut cache = SeriesCache::new("resolute");

    let pkg_a = make_pkg(
        "pkg-a",
        "1.0",
        Pocket::Release,
        Component::Main,
        Architecture::Amd64,
        vec![(DependencyType::Depends, "missing-pkg")],
        vec![],
    );
    let pkg_b = make_pkg(
        "pkg-b",
        "2.0",
        Pocket::Release,
        Component::Main,
        Architecture::Amd64,
        vec![(DependencyType::Depends, "pkg-a")],
        vec![],
    );

    cache.packages.insert("pkg-a".to_string(), vec![pkg_a]);
    cache.packages.insert("pkg-b".to_string(), vec![pkg_b]);

    let filter = QueryFilter::builder("resolute").build().unwrap();
    let query = RaptQuery::new(&cache, &filter);

    let unmet_output = query.unmet();
    assert!(unmet_output.contains("Package pkg-a version 1.0 has an unmet dep:"));
    assert!(unmet_output.contains("Depends: missing-pkg"));
    assert!(!unmet_output.contains("Package pkg-b"));

    let dump_output = query.dump();
    assert!(dump_output.contains("Using Versioning System: Standard .deb"));
    assert!(dump_output.contains("Package: pkg-a"));
    assert!(dump_output.contains("Package: pkg-b"));
}

#[test]
fn test_pocket_and_component_filtering() {
    let mut cache = SeriesCache::new("resolute");

    let pkg_release = make_pkg(
        "my-tool",
        "1.0",
        Pocket::Release,
        Component::Main,
        Architecture::Amd64,
        vec![],
        vec![],
    );
    let pkg_proposed = make_pkg(
        "my-tool",
        "1.1",
        Pocket::Proposed,
        Component::Main,
        Architecture::Amd64,
        vec![],
        vec![],
    );

    cache
        .packages
        .insert("my-tool".to_string(), vec![pkg_release, pkg_proposed]);

    // Default filter only includes release, updates, security (not proposed)
    let default_filter = QueryFilter::builder("resolute").build().unwrap();
    let query_default = RaptQuery::new(&cache, &default_filter);
    let show_default = query_default
        .show(&PackageTarget::new("my-tool", None::<String>))
        .unwrap();
    assert!(show_default.contains("Version: 1.0"));
    assert!(!show_default.contains("Version: 1.1"));

    // Filter including proposed
    let proposed_filter = QueryFilter::builder("resolute")
        .pockets(vec![Pocket::Proposed])
        .build()
        .unwrap();
    let query_proposed = RaptQuery::new(&cache, &proposed_filter);
    let show_proposed = query_proposed
        .show(&PackageTarget::new("my-tool", None::<String>))
        .unwrap();
    assert!(!show_proposed.contains("Version: 1.0"));
    assert!(show_proposed.contains("Version: 1.1"));
}
