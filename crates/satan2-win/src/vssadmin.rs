use std::process::Command;

pub fn delete_all(volume: Option<&str>) -> Result<(), String> {
    let mut args = vec!["delete", "shadows", "/quiet"];
    if volume.is_none() {
        args.push("/all");
    }

    let vol_arg;
    if let Some(vol) = volume {
        vol_arg = format!("/for={}", vol);
        args.push(&vol_arg);
    }

    let status = Command::new("vssadmin")
        .args(&args)
        .status()
        .map_err(|e| format!("vssadmin spawn failed: {}", e))?;

    if !status.success() {
        return Err(format!("vssadmin exited with: {:?}", status.code()));
    }
    Ok(())
}
