// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold Debian provisioning shared by product frontends.
pub const STANDARD: &str = "ca-certificates curl wget git openssh-client nano vim-tiny less procps psmisc iproute2 iputils-ping bind9-dnsutils netcat-openbsd rsync unzip zip xz-utils file bash-completion tzdata";
pub const DEVELOPMENT: &str =
    "build-essential pkgconf python3 python3-venv python3-pip cmake ninja-build";
pub fn debian_script(profile: &str, systemd: bool) -> Result<String, &'static str> {
    let mut packages = match profile {
        "minimal" => String::new(),
        "standard" => STANDARD.into(),
        "development" => format!("{STANDARD} {DEVELOPMENT}"),
        _ => return Err("packages must be minimal, standard or development"),
    };
    if systemd {
        packages.push_str(" systemd dbus");
    }
    if packages.is_empty() {
        return Ok("echo 'Base environment ready.'".into());
    }
    Ok(format!(
        r#"ready=yes
for package in {packages}; do
    if [ "$(dpkg-query -W -f='${{Status}}' "$package" 2>/dev/null)" != 'install ok installed' ]; then ready=no; break; fi
done
if [ "$ready" = yes ]; then echo 'Debian packages already installed.'; exit 0; fi
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=30 update --error-on=any
apt-get install -y --no-install-recommends {packages}
apt-get clean
"#
    ))
}
