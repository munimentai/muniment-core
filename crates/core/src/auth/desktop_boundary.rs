//! The desktop has no credential-store path, even when Cargo unifies runtime features.

use std::path::{Path, PathBuf};
use syn::visit::{self, Visit};
use syn::{Attribute, Meta};

fn test_only(attrs: &[Attribute]) -> bool {
    fn requires_test(meta: &Meta) -> bool {
        match meta {
            Meta::Path(path) => path.is_ident("test"),
            Meta::List(list) if list.path.is_ident("all") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated,
                )
                .unwrap()
                .iter()
                .any(requires_test),
            _ => false,
        }
    }
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg") && requires_test(&attr.parse_args::<Meta>().unwrap())
    })
}

struct DesktopBoundary {
    directory: PathBuf,
    files: usize,
    launch_boundaries: usize,
}

impl DesktopBoundary {
    fn file(&mut self, path: &Path, directory: PathBuf) {
        let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
        let previous = std::mem::replace(&mut self.directory, directory);
        self.files += 1;
        self.visit_file(&file);
        self.directory = previous;
    }
}

impl<'ast> Visit<'ast> for DesktopBoundary {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs = match item {
            syn::Item::Const(item) => &item.attrs,
            syn::Item::Enum(item) => &item.attrs,
            syn::Item::Fn(item) => &item.attrs,
            syn::Item::Impl(item) => &item.attrs,
            syn::Item::Macro(item) => &item.attrs,
            syn::Item::Mod(item) => &item.attrs,
            syn::Item::Static(item) => &item.attrs,
            syn::Item::Struct(item) => &item.attrs,
            syn::Item::Trait(item) => &item.attrs,
            syn::Item::Type(item) => &item.attrs,
            syn::Item::Use(item) => &item.attrs,
            _ => return visit::visit_item(self, item),
        };
        if !test_only(attrs) {
            visit::visit_item(self, item);
        }
    }

    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        let attrs = match expr {
            syn::Expr::Return(expr) => &expr.attrs,
            syn::Expr::Block(expr) => &expr.attrs,
            syn::Expr::If(expr) => &expr.attrs,
            _ => return visit::visit_expr(self, expr),
        };
        if !test_only(attrs) {
            visit::visit_expr(self, expr);
        }
    }

    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let forbidden = [
            "keyring",
            "keychain",
            "security_framework",
            "security_framework_sys",
            "KeyringNativeCredentialStore",
            "NativeCredentialStore",
            "NativeCredentialBackend",
            "CoherentNativeCredentialStore",
            "fetch_native_grant",
            "renew_native_grant",
            "inspect_native_chat_session",
            "chat_prompt",
            "thread_history",
        ];
        assert!(
            !forbidden.contains(&ident.to_string().as_str()),
            "The desktop must use attach instead of {ident} in {}.",
            self.directory.display()
        );
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        // The attach client exposes this display-only method.
        if call.method == "thread_history" {
            self.visit_expr(&call.receiver);
            for argument in &call.args {
                self.visit_expr(argument);
            }
        } else {
            visit::visit_expr_method_call(self, call);
        }
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        assert!(
            !item.attrs.iter().any(|attr| attr.path().is_ident("path")),
            "A source path needs a credential boundary review."
        );
        if let Some((_, items)) = &item.content {
            let previous = self.directory.clone();
            self.directory.push(item.ident.to_string());
            for item in items {
                self.visit_item(item);
            }
            self.directory = previous;
        } else {
            let name = item.ident.to_string();
            let path = self.directory.join(format!("{name}.rs"));
            let path = if path.is_file() {
                path
            } else {
                self.directory.join(&name).join("mod.rs")
            };
            self.file(&path, self.directory.join(name));
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if item
            .trait_
            .as_ref()
            .is_some_and(|(_, path, _)| path.segments.last().unwrap().ident == "PiLaunchBoundaries")
        {
            self.launch_boundaries += 1;
            for required in ["renew_chat_grant", "inspect_chat_session"] {
                assert!(item.items.iter().any(|item| matches!(item, syn::ImplItem::Fn(method) if method.sig.ident == required && !test_only(&method.attrs))),
                    "The desktop must override the credential-backed default for {required}.");
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if let syn::UseTree::Path(path) = &item.tree {
            assert!(
                path.ident != "muniment_runtime",
                "The desktop must name runtime lifecycle helpers without an import alias."
            );
        }
        visit::visit_item_use(self, item);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        assert!(
            !invocation.path.is_ident("include"),
            "A source include needs a credential boundary review."
        );
        visit::visit_macro(self, invocation);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<_> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if segments
            .first()
            .is_some_and(|name| name == "muniment_runtime")
        {
            assert!(
                matches!(
                    segments.get(1).map(String::as_str),
                    Some(
                        "install_lock"
                            | "profile_directory"
                            | "adopt_state_directory"
                            | "WindowsDiagnosticEvent"
                            | "windows_local_app_data"
                            | "write_windows_diagnostic"
                            | "clear_windows_crash_window"
                    )
                ),
                "The desktop may use runtime lifecycle helpers, not runtime session services."
            );
        }
        visit::visit_path(self, path);
    }
}

#[test]
fn desktop_has_no_credential_store_call_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../src");
    let mut boundary = DesktopBoundary {
        directory: root.clone(),
        files: 0,
        launch_boundaries: 0,
    };
    boundary.file(&root.join("main.rs"), root.clone());
    // The Windows sandbox host loads the desktop as a library. Keep its one
    // reviewed include explicit, then scan every module in the shared entry.
    assert_eq!(
        std::fs::read_to_string(root.join("lib.rs")).unwrap().trim(),
        "include!(\"desktop.rs\");"
    );
    boundary.file(&root.join("desktop.rs"), root);
    assert!(boundary.files > 20);
    assert_eq!(boundary.launch_boundaries, 1);
}

#[test]
fn boundary_checks_production_and_inactive_platform_code() {
    let test: syn::ItemFn = syn::parse_quote!(
        #[cfg(test)]
        fn example() {}
    );
    assert!(test_only(&test.attrs));
    let production: syn::ItemFn = syn::parse_quote!(
        #[cfg(not(test))]
        fn example() {}
    );
    assert!(!test_only(&production.attrs));
    for source in [
        "#[cfg(target_os = \"macos\")] fn example() { keyring::Entry::new(\"service\", \"user\"); }",
        "use muniment_core::auth::KeyringNativeCredentialStore as Store;",
        "fn example() { muniment_runtime::service::session::session_status(); }",
        "impl PiLaunchBoundaries for Shell {}",
        "use muniment_runtime::service::session::session_status as status;",
        "include!(\"credential_store.rs\");",
    ] {
        let file = syn::parse_file(source).unwrap();
        assert!(std::panic::catch_unwind(|| {
            let mut boundary = DesktopBoundary { directory: PathBuf::new(), files: 0, launch_boundaries: 0 };
            boundary.visit_file(&file);
        }).is_err());
    }
}
