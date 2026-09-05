#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
umask 022

workspace_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo_root/Cargo.toml" | head -n 1)"
version="${BORONDNS_RPM_VERSION:-$workspace_version}"
release="${BORONDNS_RPM_RELEASE:-1}"
architecture="${BORONDNS_RPM_ARCHITECTURE:-x86_64}"
dist_dir="${BORONDNS_DIST_DIR:-$repo_root/target/dist}"
borondns_bin="${BORONDNS_RPM_BORONDNS_BIN:-}"
boron_gun_bin="${BORONDNS_RPM_BORON_GUN_BIN:-}"
source_date_epoch="${SOURCE_DATE_EPOCH:-}"

[[ "$version" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]
[[ "$release" =~ ^[0-9][0-9A-Za-z._+~]*$ ]]
[[ "$architecture" =~ ^[a-zA-Z0-9_]+$ ]]
command -v rpmbuild >/dev/null || {
    printf 'package-rpm requires rpmbuild (install rpm-build)\n' >&2
    exit 1
}

if [[ -z "$source_date_epoch" ]]; then
    source_date_epoch="$(git -C "$repo_root" show -s --format=%ct HEAD)"
fi
[[ "$source_date_epoch" =~ ^[0-9]+$ ]]

if [[ -z "$borondns_bin" ]]; then
    candidates=("$dist_dir"/borondns-*-x86_64-unknown-linux-musl.bin)
    ((${#candidates[@]} == 1)) || {
        printf 'expected one packaged BoronDNS binary\n' >&2
        exit 1
    }
    borondns_bin="${candidates[0]}"
fi
if [[ -z "$boron_gun_bin" ]]; then
    candidates=("$dist_dir"/borondns-*-x86_64-unknown-linux-musl-boron-gun.bin)
    ((${#candidates[@]} == 1)) || {
        printf 'expected one packaged BoronGun binary\n' >&2
        exit 1
    }
    boron_gun_bin="${candidates[0]}"
fi
for binary in "$borondns_bin" "$boron_gun_bin"; do
    [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] || {
        printf 'RPM input must be an executable regular file: %s\n' "$binary" >&2
        exit 1
    }
done

mkdir -p "$dist_dir"
dist_dir="$(realpath -e "$dist_dir")"
build_root="$(mktemp -d "${TMPDIR:-/tmp}/borondns-rpm.XXXXXXXX")"
trap 'rm -rf -- "$build_root"' EXIT INT TERM HUP
install -d -m 0755 "$build_root/SOURCES" "$build_root/SPECS"
install -m 0755 "$borondns_bin" "$build_root/SOURCES/borondns"
install -m 0755 "$boron_gun_bin" "$build_root/SOURCES/boron-gun"
install -m 0644 "$repo_root/packaging/deb/borondns.service" "$build_root/SOURCES/borondns.service"
install -m 0644 "$repo_root/packaging/rpm/README.rpm" "$build_root/SOURCES/README.rpm"
install -m 0644 "$repo_root/packaging/installer/README.install.md" "$build_root/SOURCES/README.install.md"
install -m 0644 "$repo_root/config/borondns.example.toml" "$build_root/SOURCES/config.toml"
install -m 0644 "$repo_root/LICENSE-MIT" "$repo_root/LICENSE-APACHE" "$build_root/SOURCES/"

cat >"$build_root/SPECS/borondns.spec" <<'EOF'
Name:           borondns
Version:        %{borondns_version}
Release:        %{borondns_release}
Summary:        High-performance secondary authoritative DNS server
License:        MIT OR Apache-2.0
URL:            https://github.com/Integrity-Ltd/BoronDNS
BuildArch:      %{borondns_architecture}
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
BoronDNS is a secondary-only authoritative DNS server with static MUSL
executables. This package also includes the BoronGun load generator.

%prep

%build

%install
install -d -m 0755 %{buildroot}%{_bindir} %{buildroot}%{_unitdir}
install -d -m 0755 %{buildroot}%{_docdir}/borondns/examples
install -d -m 0750 %{buildroot}%{_sysconfdir}/borondns-secondary
install -d -m 0750 %{buildroot}%{_sharedstatedir}/borondns
install -d -m 0770 %{buildroot}%{_sharedstatedir}/borondns/zone-cache
install -m 0755 %{_sourcedir}/borondns %{buildroot}%{_bindir}/borondns
install -m 0755 %{_sourcedir}/boron-gun %{buildroot}%{_bindir}/boron-gun
install -m 0644 %{_sourcedir}/borondns.service %{buildroot}%{_unitdir}/borondns.service
install -m 0644 %{_sourcedir}/README.rpm %{buildroot}%{_docdir}/borondns/README.rpm
install -m 0644 %{_sourcedir}/README.install.md %{buildroot}%{_docdir}/borondns/README.install.md
install -m 0644 %{_sourcedir}/config.toml %{buildroot}%{_docdir}/borondns/examples/config.toml
install -m 0644 %{_sourcedir}/LICENSE-MIT %{_sourcedir}/LICENSE-APACHE %{buildroot}%{_docdir}/borondns/

%pre
if [ "$1" -eq 1 ] && [ -e /etc/systemd/system/borondns.service ]; then
    echo 'BoronDNS: remove or migrate /etc/systemd/system/borondns.service before installing the RPM' >&2
    exit 1
fi
getent group borondns >/dev/null 2>&1 || groupadd --system borondns
getent passwd borondns >/dev/null 2>&1 || \
    useradd --system --gid borondns --home-dir /var/lib/borondns \
        --no-create-home --shell /sbin/nologin borondns

%post
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" -eq 1 ]; then
    systemctl preset borondns.service >/dev/null 2>&1 || true
else
    systemctl try-restart borondns.service >/dev/null 2>&1 || true
fi

%preun
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now borondns.service >/dev/null 2>&1 || true
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || true

%files
%license %{_docdir}/borondns/LICENSE-MIT
%license %{_docdir}/borondns/LICENSE-APACHE
%doc %{_docdir}/borondns/README.rpm
%doc %{_docdir}/borondns/README.install.md
%doc %{_docdir}/borondns/examples/config.toml
%{_bindir}/borondns
%{_bindir}/boron-gun
%{_unitdir}/borondns.service
%dir %attr(0750,root,borondns) %{_sysconfdir}/borondns-secondary
%dir %attr(0750,root,borondns) %{_sharedstatedir}/borondns
%dir %attr(0770,root,borondns) %{_sharedstatedir}/borondns/zone-cache

EOF

SOURCE_DATE_EPOCH="$source_date_epoch" rpmbuild --define "_topdir $build_root" \
    --define "borondns_version $version" --define "borondns_release $release" \
    --define "borondns_architecture $architecture" \
    --define "_unitdir /usr/lib/systemd/system" \
    --define "_buildhost reproducible.invalid" \
    --define "__os_install_post %{nil}" \
    --define "_source_date_epoch $source_date_epoch" \
    --define "clamp_mtime_to_source_date_epoch 1" --define "use_source_date_epoch_as_buildtime 1" \
    -bb "$build_root/SPECS/borondns.spec" >/dev/null

built=("$build_root/RPMS/$architecture/borondns-$version-$release".*.rpm)
((${#built[@]} == 1))
output="$dist_dir/${built[0]##*/}"
checksum="$output.sha256"
install -m 0644 "${built[0]}" "$output"
(
    cd "$dist_dir"
    sha256sum -- "${output##*/}" >"${checksum##*/}"
)
printf '%s\n' "$output"
