"""The package-manager manifests for a release, rendered from its archives.

The GitHub release is the hub: the Homebrew formula and the AUR package point
at its archives by URL and SHA-256, so every channel installs the bytes the
release published.

    python3 packaging/channels.py <version> <owner/repo> <archives> <out>

writes <out>/homebrew/nitromta.rb, and <out>/aur/PKGBUILD with its .SRCINFO.
"""

import hashlib
import pathlib
import sys

HOMEPAGE = "https://nitromta.com"
DESCRIPTION = "Self-hosted mail delivery engine that speaks the Amazon SES v2 API"
LICENSE = "Apache-2.0"
TARGETS = {
    "macos-arm": "aarch64-macos",
    "macos-intel": "x86_64-macos",
    "linux-arm": "aarch64-linux",
    "linux-intel": "x86_64-linux",
}


def main(version, repo, archives, out):
    archives = pathlib.Path(archives)
    out = pathlib.Path(out)
    files = {}
    for key, target in TARGETS.items():
        name = f"nitromta-{version}-{target}.tar.gz"
        path = archives / name
        if not path.is_file():
            sys.exit(f"{name} is not among the release's archives")
        files[key] = (
            f"https://github.com/{repo}/releases/download/v{version}/{name}",
            hashlib.sha256(path.read_bytes()).hexdigest(),
        )
    write(out / "homebrew" / "nitromta.rb", homebrew(version, files))
    write(out / "aur" / "PKGBUILD", pkgbuild(version, files))
    write(out / "aur" / ".SRCINFO", srcinfo(version, files))


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def homebrew(version, files):
    def source(key):
        url, sha = files[key]
        return f'      url "{url}"\n      sha256 "{sha}"'

    return f'''class Nitromta < Formula
  desc "{DESCRIPTION}"
  homepage "{HOMEPAGE}"
  version "{version}"
  license "{LICENSE}"

  on_macos do
    on_arm do
{source("macos-arm")}
    end
    on_intel do
{source("macos-intel")}
    end
  end

  on_linux do
    on_arm do
{source("linux-arm")}
    end
    on_intel do
{source("linux-intel")}
    end
  end

  def install
    bin.install "nitromta"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/nitromta --version")
  end
end
'''


def pkgbuild(version, files):
    return f'''# Maintainer: auscaster <hi@auscaster.com>
pkgname=nitromta-bin
pkgver={version}
pkgrel=1
pkgdesc="{DESCRIPTION}"
arch=('x86_64' 'aarch64')
url="{HOMEPAGE}"
license=('{LICENSE}')
depends=('glibc' 'ca-certificates')
provides=('nitromta')
conflicts=('nitromta')
source_x86_64=("{files["linux-intel"][0]}")
source_aarch64=("{files["linux-arm"][0]}")
sha256sums_x86_64=('{files["linux-intel"][1]}')
sha256sums_aarch64=('{files["linux-arm"][1]}')

package() {{
  cd "nitromta-${{pkgver}}-${{CARCH}}-linux"
  install -Dm755 nitromta "$pkgdir/usr/bin/nitromta"
  install -Dm644 nitromta.service "$pkgdir/usr/lib/systemd/system/nitromta.service"
  install -Dm644 nitromta.sysusers "$pkgdir/usr/lib/sysusers.d/nitromta.conf"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 NOTICE "$pkgdir/usr/share/licenses/$pkgname/NOTICE"
}}
'''


def srcinfo(version, files):
    return f"""pkgbase = nitromta-bin
\tpkgdesc = {DESCRIPTION}
\tpkgver = {version}
\tpkgrel = 1
\turl = {HOMEPAGE}
\tarch = x86_64
\tarch = aarch64
\tlicense = {LICENSE}
\tdepends = glibc
\tdepends = ca-certificates
\tprovides = nitromta
\tconflicts = nitromta
\tsource_x86_64 = {files["linux-intel"][0]}
\tsha256sums_x86_64 = {files["linux-intel"][1]}
\tsource_aarch64 = {files["linux-arm"][0]}
\tsha256sums_aarch64 = {files["linux-arm"][1]}

pkgname = nitromta-bin
"""


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    main(*sys.argv[1:])
