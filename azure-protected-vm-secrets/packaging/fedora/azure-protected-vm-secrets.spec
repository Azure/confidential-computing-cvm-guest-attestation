# Spec file for azure-protected-vm-secrets, the Azure CVM Secrets
# Provisioning Library (SSPL) and its CLI front-end. Authored for Fedora
# rawhide / EPEL 10+; see ./README.md for build instructions and the
# project's `plan to publish packages in fedora.md` for context.
#
# Source code lives in the azure-protected-vm-secrets/ subdirectory of the
# Azure/confidential-computing-cvm-guest-attestation monorepo on GitHub.
# We use GitHub's auto-generated tag tarball and re-root via %%autosetup -n
# into that subdirectory. Pattern based on SourceURL.adoc §Git Tags, extended
# for the subdirectory case (the doc explicitly endorses comments above
# Source: to explain non-standard situations).

Name:           azure-protected-vm-secrets
Version:        1.0.9
Release:        %autorelease
Summary:        Decrypts host-protected secrets in Azure Confidential VMs

License:        MIT
URL:            https://github.com/Azure/confidential-computing-cvm-guest-attestation
# Source0 is a subtree tarball of just the azure-protected-vm-secrets/ component,
# NOT GitHub's auto-generated whole-repo tag archive. The whole-repo archive is
# not byte-reproducible (breaks the "sources match upstream" checksum check) and
# carries ~27 MB of unrelated monorepo content (e.g. a demo .mp4) that is
# impermissible in the SRPM. The subtree tarball is produced from the upstream
# release tag azure-protected-vm-secrets-v%%{version} by the checked-in helper
# packaging/fedora/generate-source-tarball.sh (git archive of the component
# subtree). It is a bare filename (uploaded to the Fedora lookaside cache via
# `fedpkg new-sources`), not a URL, to avoid pointing at a personal fork.
Source0:        %{name}-%{version}.tar.gz
# Man page for the CLI, maintained in this packaging directory (upstream
# does not yet ship one; SHOULD per Fedora Packaging Guidelines §Manpages).
Source1:        azure-protected-secrets-tool.1
# The upstream LICENSE lives at the monorepo root, outside the component
# subtree tarball, so it is carried as a separate Source rather than from Source0.
Source2:        LICENSE

# Azure Confidential VMs are x86_64 (SEV-SNP / TDX); CVM detection uses x86
# CPUID and there is no aarch64 implementation, so restrict to x86_64.
ExclusiveArch:  %{x86_64}

BuildRequires:  cmake
BuildRequires:  gcc-c++
BuildRequires:  make
BuildRequires:  pkgconfig
BuildRequires:  boost-devel
BuildRequires:  openssl-devel
BuildRequires:  systemd-devel
BuildRequires:  tpm2-tss-devel
BuildRequires:  nlohmann-json-devel
BuildRequires:  gtest-devel
BuildRequires:  gmock-devel

# %%cmake will install the shared object to %%{_libdir}; the main package pulls
# in the runtime library via the -libs subpackage.
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}

# Wrap the multi-line description via %%{expand} so the paragraph is passed as a
# single expanded value; a raw multi-line %%description can be mangled/truncated.
# (Per reviewer feedback; common Fedora idiom.)
%global _description %{expand:
azure-protected-vm-secrets detects the confidential-computing environment and
decrypts host-provisioned secrets on Azure Confidential VMs (AMD SEV-SNP,
Intel TDX). The package contains the
azure-protected-secrets-tool CLI for invoking the supported operations
(is-cvm, is-secrets-provisioning-enabled, unprotect-secret,
validate-imds-metadata); the runtime shared library is in the -libs
subpackage and the C header for linking against it is in the -devel
subpackage.}

# Same %%{expand} wrapping for the subpackage descriptions so their multi-line
# paragraphs are passed as single expanded values (avoids mangling/truncation).
%global _libs_description %{expand:
Shared library implementing the host-protected-secret unprotect and
secrets-provisioning helpers consumed by azure-protected-vm-secrets and any
third-party application that links directly against
libazure_protected_vm_secrets.}

%global _devel_description %{expand:
C header file and unversioned shared-library symlink for building software
that links against libazure_protected_vm_secrets.}

%description %{_description}

%package libs
Summary:        Runtime shared library for %{name}
# -libs is the leaf runtime library: it is required BY the main package and by
# -devel, so it intentionally carries no sibling Requires (a Requires back on
# the main CLI package would be circular). This satisfies the Fedora
# "fully-versioned dependency in subpackages" guidance, which applies to the
# consuming subpackages (main, -devel) that use %%{?_isa}-qualified, fully
# versioned Requires below.

%description libs %{_libs_description}

%package devel
Summary:        Development files for %{name}
# Fully-versioned, ISA-qualified dependency on the runtime library, per the
# Fedora Packaging Guidelines for -devel subpackages.
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}

%description devel %{_devel_description}

%prep
# Source0 is a subtree tarball whose top-level directory is
# %{name}-%{version}/ (see git archive --prefix at release time).
%autosetup -n %{name}-%{version}

%conf
%cmake

%build
%cmake_build

%install
%cmake_install
# The upstream LICENSE lives at the monorepo root (outside this component
# subtree), so it is shipped as Source2 and staged into the build dir so
# %%license can reference it below. -p preserves the original timestamp.
install -D -p -m 0644 %{SOURCE2} %{_builddir}/%{buildsubdir}/LICENSE
# Install the CLI man page (RPM compresses it automatically).
install -D -p -m 0644 %{SOURCE1} %{buildroot}%{_mandir}/man1/azure-protected-secrets-tool.1
# Keep the man page .TH version in sync with the package version automatically,
# so the man page never drifts on a version bump.
sed -i 's/azure-protected-vm-secrets [0-9]\+\.[0-9]\+\.[0-9]\+/azure-protected-vm-secrets %{version}/' \
    %{buildroot}%{_mandir}/man1/azure-protected-secrets-tool.1

%check
%ctest

%files
%license LICENSE
%doc README.md
%{_bindir}/azure-protected-secrets-tool
%{_mandir}/man1/azure-protected-secrets-tool.1*

%files libs
%license LICENSE
%{_libdir}/libazure_protected_vm_secrets.so.%{version}
%{_libdir}/libazure_protected_vm_secrets.so.1

%files devel
%{_includedir}/SecretsProvisioningLibrary.h
%{_libdir}/libazure_protected_vm_secrets.so

%changelog
%autochangelog
