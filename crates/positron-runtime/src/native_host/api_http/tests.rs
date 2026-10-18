use super::*;
use crate::{BootstrapPaths, InitializationPlan, InstanceBootstrap};
use positron_kernel::{MountQualification, ResourceAmounts, ResourceDimension, WorkClaim};

#[test]
fn http_body_bytes_retain_real_governor_capacity_through_transport_frame_clones()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!(
        "p-http-body-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir(&root)?;
    for name in ["data", "secrets"] {
        std::fs::create_dir(root.join(name))?;
        std::fs::set_permissions(root.join(name), std::fs::Permissions::from_mode(0o700))?;
    }
    let paths = BootstrapPaths::new(
        &root.join("data"),
        &root.join("secrets"),
        MountQualification::LocalHost,
    )?;
    let instance = InstanceBootstrap::initialize(&paths, InitializationPlan::non_interactive())?;
    let governor = instance.resource_governor();
    let before = governor.inspect()?.usage(ResourceDimension::MemoryBytes);
    let charge = 65_536;
    for emit_frame in [true, false] {
        let reservation = governor
            .reserve(WorkClaim::system_diagnostics(ResourceAmounts::only(
                ResourceDimension::MemoryBytes,
                charge,
            )?)?)?
            .transfer();
        let mut native = NativeResponse::empty(200);
        native.body = vec![42; charge as usize];
        native.response_reservation = Some(Box::new(reservation));
        let mut response = response_from_native(native);
        assert_eq!(
            response
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok()),
            Some("65536")
        );
        assert_eq!(
            governor.inspect()?.usage(ResourceDimension::MemoryBytes),
            before + charge
        );
        if emit_frame {
            let mut context = Context::from_waker(std::task::Waker::noop());
            let Poll::Ready(Some(Ok(frame))) =
                Pin::new(response.body_mut()).poll_frame(&mut context)
            else {
                return Err("missing HTTP body frame".into());
            };
            let bytes = frame.into_data().map_err(|_| "unexpected trailer")?;
            let retry_copy = bytes.clone();
            drop(bytes);
            drop(response);
            assert_eq!(retry_copy.as_ref(), vec![42; charge as usize]);
            assert_eq!(
                governor.inspect()?.usage(ResourceDimension::MemoryBytes),
                before + charge
            );
            drop(retry_copy);
        } else {
            drop(response);
        }
        assert_eq!(
            governor.inspect()?.usage(ResourceDimension::MemoryBytes),
            before
        );
    }
    drop(instance);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
