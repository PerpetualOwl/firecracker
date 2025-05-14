# Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Integration tests for the virtio-pmem device.

import os
import pytest
import host_tools.logging as log_tools
from framework.utils import run_cmd, UffdHandler
from framework.artifacts import NetIfaceConfig

# Assuming standard fixtures and helpers are available.
# Adjust imports if necessary based on actual framework structure.


# Define guest kernel and rootfs requirements (ensure virtio_pmem, dax, ext4 support)
# These might be defined globally or passed via fixtures.
PMEM_KERNEL = "path/to/kernel-with-pmem-dax.bin" # Replace with actual kernel artifact name/path
PMEM_ROOTFS = "path/to/rootfs-with-pmem-tools.ext4" # Replace with actual rootfs artifact name/path
PMEM_MEM_MIB = 256
PMEM_VCPUS = 1

# Size for the pmem device backing file (e.g., 64 MiB)
PMEM_SIZE_MIB = 64
PMEM_DRIVE_ID = "pmem0"
PMEM_GUEST_DEV = "/dev/pmem0"
PMEM_MOUNT_POINT = "/mnt/pmem_test"
TEST_FILENAME = "test_file.txt"
TEST_DATA_INITIAL = "Hello Virtio-PMEM!"
TEST_DATA_PERSIST = "Data that persists!"


@pytest.fixture
def pmem_backing_file(tmp_path):
    """Create a backing file for the pmem device."""
    file_path = tmp_path / "pmem_backing.img"
    size_bytes = PMEM_SIZE_MIB * 1024 * 1024
    run_cmd(f"truncate -s {size_bytes} {file_path}")
    return file_path


def _guest_pmem_setup(ssh_connection):
    """Common guest setup: check device, create fs, mount."""
    # Check if pmem device exists
    cmd = f"ls {PMEM_GUEST_DEV}"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to find {PMEM_GUEST_DEV}: {stderr}"

    # Create filesystem (ext4)
    cmd = f"mkfs.ext4 {PMEM_GUEST_DEV}"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to create filesystem on {PMEM_GUEST_DEV}: {stderr}"

    # Create mount point
    cmd = f"mkdir -p {PMEM_MOUNT_POINT}"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to create mount point {PMEM_MOUNT_POINT}: {stderr}"

    # Mount with DAX option
    cmd = f"mount -o dax {PMEM_GUEST_DEV} {PMEM_MOUNT_POINT}"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to mount {PMEM_GUEST_DEV} with DAX: {stderr}"

    # Verify DAX mount option is active
    cmd = f"mount | grep {PMEM_MOUNT_POINT} | grep dax"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"DAX option not active for mount {PMEM_MOUNT_POINT}: {stderr}"


def _guest_pmem_cleanup(ssh_connection):
    """Unmount the pmem device in the guest."""
    cmd = f"umount {PMEM_MOUNT_POINT}"
    ssh_connection.execute_command(cmd) # Ignore errors, might already be unmounted


def test_pmem_dax_mount_and_io(test_microvm_with_ssh, network_config, pmem_backing_file):
    """
    Test basic virtio-pmem functionality: DAX mount and simple I/O.
    """
    vm = test_microvm_with_ssh
    vm.spawn()

    # Set up VM networking.
    vm.network_config = network_config
    vm.basic_config(
        vcpu_count=PMEM_VCPUS,
        mem_size_mib=PMEM_MEM_MIB,
        kernel_image_path=PMEM_KERNEL, # Use appropriate kernel
        rootfs_path=PMEM_ROOTFS,       # Use appropriate rootfs
        # Add kernel boot args if needed (e.g., console=ttyS0)
    )

    # Add the pmem device
    response = vm.pmem.put(
        drive_id=PMEM_DRIVE_ID,
        path_on_host=str(pmem_backing_file),
        size_mib=PMEM_SIZE_MIB,
        use_dax=True,
        is_read_only=False
    )
    assert vm.api_session.is_good_response(response.status_code)

    vm.start()
    ssh_connection = vm.ssh_connection

    # Setup pmem device in guest
    _guest_pmem_setup(ssh_connection)

    # Basic I/O test
    test_file_path = os.path.join(PMEM_MOUNT_POINT, TEST_FILENAME)
    cmd = f"echo '{TEST_DATA_INITIAL}' > {test_file_path}"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to write to {test_file_path}: {stderr}"

    cmd = f"cat {test_file_path}"
    exit_code, stdout, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to read from {test_file_path}: {stderr}"
    assert stdout.strip() == TEST_DATA_INITIAL, \
        f"Read data mismatch: expected '{TEST_DATA_INITIAL}', got '{stdout.strip()}'"

    # Cleanup
    _guest_pmem_cleanup(ssh_connection)


def test_pmem_persistence(test_microvm_with_ssh, network_config, pmem_backing_file):
    """
    Test that data written to the pmem device persists across a VM reboot.
    """
    vm = test_microvm_with_ssh
    vm.spawn()
    vm.network_config = network_config
    vm.basic_config(
        vcpu_count=PMEM_VCPUS,
        mem_size_mib=PMEM_MEM_MIB,
        kernel_image_path=PMEM_KERNEL,
        rootfs_path=PMEM_ROOTFS,
    )
    vm.pmem.put(
        drive_id=PMEM_DRIVE_ID,
        path_on_host=str(pmem_backing_file),
        size_mib=PMEM_SIZE_MIB,
        use_dax=True,
        is_read_only=False
    )
    vm.start()
    ssh_connection = vm.ssh_connection

    # Initial setup and write data
    _guest_pmem_setup(ssh_connection)
    test_file_path = os.path.join(PMEM_MOUNT_POINT, TEST_FILENAME)
    cmd = f"echo '{TEST_DATA_PERSIST}' > {test_file_path}"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to write persistence data: {stderr}"

    # Ensure data reaches host backing file (sync should trigger FLUSH)
    cmd = "sync"
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Guest sync command failed: {stderr}"

    _guest_pmem_cleanup(ssh_connection)

    # Reboot the VM (trigger stop/start or specific reboot action)
    # Using microvm.kill() and restarting simulates a less graceful stop.
    # A graceful shutdown `reboot` command inside guest might be better if available.
    vm.kill()

    # Respawn and restart VM with the *same* backing file configuration
    vm.spawn() # Respawn the process
    vm.network_config = network_config # Reconfigure network
    vm.basic_config( # Reconfigure basic VM settings
        vcpu_count=PMEM_VCPUS,
        mem_size_mib=PMEM_MEM_MIB,
        kernel_image_path=PMEM_KERNEL,
        rootfs_path=PMEM_ROOTFS,
    )
    vm.pmem.put( # Re-attach the same pmem device
        drive_id=PMEM_DRIVE_ID,
        path_on_host=str(pmem_backing_file),
        size_mib=PMEM_SIZE_MIB,
        use_dax=True,
        is_read_only=False
    )
    vm.start() # Start the VM again
    ssh_connection = vm.ssh_connection # Get new SSH connection

    # Re-setup pmem device in guest (mount only, filesystem should persist)
    cmd = f"mkdir -p {PMEM_MOUNT_POINT}" # Ensure mount point exists
    ssh_connection.execute_command(cmd)
    cmd = f"mount -o dax {PMEM_GUEST_DEV} {PMEM_MOUNT_POINT}" # Remount
    exit_code, _, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to remount {PMEM_GUEST_DEV} after reboot: {stderr}"

    # Verify persisted data
    cmd = f"cat {test_file_path}"
    exit_code, stdout, stderr = ssh_connection.execute_command(cmd)
    assert exit_code == 0, f"Failed to read persisted data from {test_file_path}: {stderr}"
    assert stdout.strip() == TEST_DATA_PERSIST, \
        f"Persisted data mismatch: expected '{TEST_DATA_PERSIST}', got '{stdout.strip()}'"

    # Cleanup
    _guest_pmem_cleanup(ssh_connection)

# TODO: Add tests for read-only mode.
# TODO: Add tests for non-DAX mode (if supported/needed).
# TODO: Add tests for error conditions (e.g., backing file permissions).