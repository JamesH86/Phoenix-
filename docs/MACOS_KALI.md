# macOS Kali bridge

Phoenix keeps the Mac host clean by running registered Kali actions inside a confined container. The supported runtime choices are Docker Desktop or Colima with the Docker client. Phoenix uses the official `kalilinux/kali-rolling` image as the base for its reviewed toolkit.

## One-time host setup

Install and start one Docker-compatible runtime:

- Docker Desktop: use the installer for Apple silicon or Intel from Docker's official macOS installation page.
- Colima: install Colima and the Docker client using your organization's approved package workflow, then start Colima with its Docker runtime.

Phoenix does not silently install privileged host software. After the runtime is available:

1. Open **Operations**.
2. Select **Kali Bridge** to verify the runtime.
3. Select **Prepare Kali Toolkit** once. That one authorized action builds `phoenix-guardian-kali:latest` from the reviewed Dockerfile.
4. Select **Kali Inventory** to see which tools are genuinely installed.

## Isolation contract

Registered container actions run with:

- no host-directory mounts;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- a read-only root filesystem and bounded temporary storage;
- bounded CPU, memory, and process counts;
- no arbitrary command endpoint.

The container bridge supports defensive and explicitly authorized assessment workflows. Hardware Wi-Fi access, USB radio access, kernel modules, stealth, persistence, credential attacks, and exploit delivery are intentionally unavailable.

The official Kali base image is minimal. Phoenix's reviewed image adds a curated set of reconnaissance, HTTP, DNS, TLS, and reporting utilities; it does not pretend every Kali package is installed.
