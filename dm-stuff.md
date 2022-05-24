An brief introduction about dm-{verity, integrity, crypto} and LUKS2
====================================================================

In the context of Full Disk Encryption (FDE) can be useful to have a
better understanding of the different device mapper kernel features
that improve security via encryption, integrity or data
authentication.


dm-verity
---------

dm-verity[1] is a device mapper target that will create a new device
that will be, transparently, checked for integrity.  It is a
technology that comes from Android and ChromeOS, that are image-based
systems and / or read only systems.

Internally[2], dm-verity is creating a merkle tree of hashes of the
measured block device.  It is creating a first layers of measurements,
calculating the hash (usually SHA256, but can be changed) of all the
4K blocks of the device.  A second layer is creating calculating the
hash of another 4K blocks of hashes.  We do that until we have a root
hash that we keep outside of the system.

This tree of hashes needs to be stored.  There are two options, we can
store it in a different device or partition, or we can reuse the one
that we are measuring if we indicate an "offset" of this same device
that is not allocated by the file system.

This tree will be checked constantly during the reads operations, and
the subtree of hashes will be recalculated (from the read block until
the root hash).  This operation is O(logN), so is quite fast and
effective.  If the new root hash calculated does not match the one
expected, an IO error will be through at that moment.

The root hash calculated initially should be keep separated, as will
be used during the `open` operation of the device.  In that way, we
have one user provided "secret" that we can use to compare with.

Some key points then:

  * The merkle tree is extremely fast.  There is not much overhead of
    computation.

  * The device first needs to be filled with the filesystem and with
    the data, and then we need to format the hash device to create the
    merkle tree.

  * The device should be read - only, because a write will make a
    mismatch of the hash root instantly.

  * The initial hash root should be keep separately, maybe stored in a
    *TPM*, so when opening the device it will be compared against a
    good known value.

  * You need to reserve a second device or partition to store the
    hashes, but is easy to calculate.

  * Works on devices and on files, so is ideal to deploy
    squashfs-alike images that are signed and measured.  Once
    installed (copied) into the system, we will be sure that they are
    not tampered.  This is ideal for image-based installations.

  * The IO error is produced during the reading of the changed block,
    not during the open of the device (delayed detection)

  * If we link cryptsetup into util-linux[3] we can mount the images
    directly, using `mount` and providing directly the hash.  If not
    we will need to use `veritysetup` to open the device as an extra
    step.

A note about the last point.  The SR was reverted because introduced
new dependencies into ring0.  If we want to have it (something that
can be relevant for systemd integration), we should find an
alternative.

### Systemd

Systemd can understand dm-verity devices via the `veritytab`[4]
configuration file.  This file indicates the volume name (where is
going to be mapped), the devices for the data and the hash (merkle
tree) and the expected root hash.

There is also a `systemd-veritysetup-generator`[5] can get the kernel
command line options, and create `systemd-veritysetup`[6] service
units to attach those devices on demand.

With this generator we can send the root hash directly from the boot
loader.  Systemd will try to find the device inspecting the UUIDs from
the GPT, and matching certain sections of the hash.  In any case it is
possible to pass the data and hash devices also via the kernel command
line.

This is a mechanism that will mount the devices (or images) during
boot time, maybe in the initrd stage.

### Example

```bash
dd if=/dev/zero of=data.ext4 bs=1M count=1024
dd if=/dev/zero of=hash bs=1M count=64
mkfs.ext4 -b 4096 data.ext4
losetup /dev/loop0 data.ext4
losetup /dev/loop1 hash
mkdir drv
mount /dev/loop0 drv
rm -fr drv/lost+found/
echo "abcdefg" > drv/test.txt
umount drv

losetup -d /dev/loop0
losetup -r /dev/loop0 data.ext4

veritysetup format /dev/loop0 /dev/loop1
# HASH comes from the `format` command
veritysetup open /dev/loop0 test /dev/loop1 $HASH

# Now we can mount the test device
mount /dev/mapper/test drv

# If we link cryptsetup can be done directly, without the `open` command
mount /dev/mapper/test drv -o verity.hashdevice=/dev/loop1,verity.roothash=$HASH
```

### Btrfs and dm-verity

A dm-verity device can be created directly from one with btrfs
filesystem.  The mismatch is, naturally, when considering subvolumes,
as they lives in the same device.

Even though MicroOS present a good use case for dm-verity (because is
based on read only rootfs), there is not current way to provide a
dm-verity hash tree for a subvolume.

A good research topic can be provide the merkle tree per subvolume in
the filesystem, and provides a root hash via the `btrfs subvolume`
command.

A better alternative is to expand fs-verity (next section) to include
btrfs filesystems.

### Learn more

[1] https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html
[2] https://source.android.com/security/verifiedboot/dm-verity
[3] https://build.opensuse.org/request/show/967500
[4] https://www.freedesktop.org/software/systemd/man/veritytab.html
[5] https://www.freedesktop.org/software/systemd/man/systemd-veritysetup-generator.html
[6] https://www.freedesktop.org/software/systemd/man/systemd-veritysetup@.service.html

fs_verity
---------

fs-verity[10] provides the same transparent integrity and data
authentication features that dm-verity provides, but in the filesystem
layer.

Sadly is only supported in ext4 (and f2fs) filesystems, but should be
possible to include other like btrfs.

In the same way that dm-verity, a merkle tree is build (triggered by
an ioctl) that is stored this time inside the filesystem (no need of
an additional device).  This is done per file, and later are marked as
read only.

In this model, because is done per file, the removal of one will not
be detected and also the addition of new ones.  This shift the
security guarantees making it more similar to IMA (that is also done
per file).

There also some data authentication (that is also what EVM provides at
the same filesystem level), as the root hash (that again, is per file)
is can be signed by an user provided key.

Another difference from dm-verity is that is designed to mix verified
files (that contain the extra metadata and are read only) with normal
files (that can be changed).

Due to those divergences I did not pursue more test and research of
this solution, but all the data structures and IOCTL calls are
documented, and the uses cases described.

### Systemd

There is not direct integration with systemd as is not needed.
Mounting a device with ext4 with fs-verity enabled is transparent.

### Example

I could not find the fsverity-utils[11] in openSUSE, maybe because is
again an Android oriented feature, but a typical usage should be like:

```bash
mkfs.ext4 -O verity /dev/sda3
mount /dev/sda3 /mnt && cd /mnt

echo "this is a test" > test.txt
fsverity enable test.txt
# Get the root hash of the file
fsverity measure test.txt

# The root hash has not been signed, but we can create a certificate
# with openssl and use keyctl to register the key.  Once done that we
# can do:

sysctl fs.verity.require_signatures=1
fsverity sign test.txt test.txt.sig --key=key.pem --cert=cert.pem
fsverity enable file --signature=test.txt.sig
rm test.txt.sig
```

This was extracted from the documentation, that is excellent.

### Learn more

[10] https://www.kernel.org/doc/html/latest/filesystems/fsverity.html
[11] https://git.kernel.org/pub/scm/linux/kernel/git/ebiggers/fsverity-utils.git


dm-integrity
------------

dm-integrity provides integrity and data authentication for read-write
devices.  It creates a new block device that has some free space per
set of blocks, that can be used to store integrity information.

Now, every time that a new sector is written, the metadata gaps are
updated with some the new checksum.  The user can choose the checksum
used (provided by the kernel according to the list in `/proc/crypto`),
but can also choose an HMAC variant of those.  In this case, an user
provided (via the `integritysetup` CLI) key file will be appended to
the calculated checksum, and hashed all together using a different
hash algorithm.

This technique is the core for providing data authentication, so now
if the block device is updated from outside the system (because the
hard disk has been extracted), it will be not possible to calculate
the new corresponding metadata as the HMAC key is a secret stored in
the original system, like for example sealed by a *TPM*.

Writing new data can be more complicated, as now for each data there
is also an associated metadata (checksum) that need to be stored in
different places.  If there is a power issue, can be that the data is
stored and not the metadata, producing later a IO error (as now the
integrity checksum will not match).

To fix that dm-integrity implements an internal journal, where the
data and the checksum is copied first, synchronized and later copied
into the expected place.  This journal is optional, and a bitmap
mechanism is an alternative option that can be faster in some
situations.

Because of those gaps and the journal, the final size of the device is
a bit smaller than the original one.

One difference with dm-verity is that in dm-verity set the data device
normally, provide a filesystem and the data, and later you calculate
the hashes.  With this information now a new device can be created,
that is the one that will be mounted in the system.

But with dm-integrity you need to create first an underline new device
on top of the physical one, mount this device (that will be smaller
than the original one), and now we can apply the filesystem and the
data.  If this underline device the one that is reserving space in the
real device to store the metadata, and do the data validation.

One last point, that will be relevant later with LUKS2, is that
dm-integrity metadata can be reused for a different purpose when
dm-crypto is in place.  For example, when we are using AEAD algorithms
for data authentication, this free space is repurposed to store the
validation hash that will be used to detect any change in the
encrypted data.  There is a full set of API that allow the re-usage
for those gaps, and in this case `status` will report that no cipher
has been used to track the integrity data.

Some notes:

  * The device used to store date will be smaller that the original
    one, and the final size will depend on the options selected (block
    size, journal, etc)

  * There is a big performance lost (WIP is measuring some
    configurations with FIO), due to the journal mechanism, the hash
    algorithm used, the block size, and the HMAC function for keyed
    checksum (note that in this case the penalty is because we need to
    call two different hash functions per write)

  * The metadata can be encrypted with keyed metadata, and the TPM can
    be used to unseal the key.  This provides data authentication.

  * The IO error, when the integrity data check fails, will be
    produced when reading the changed data (delayed detection)

### Systemd

There is integration of dm-integrity with systemd, very similar as has
been done with dm-verity.

We can use the `integritytab`[21] file to indicate the device name
that will be used by the mapper, and the device path (or file).  If we
are using keyed hashes (to encrypt the metadata, but maintain the data
clean), we can pass the key file and other options.

Again we can use `systemd-integritysetup-generator`[22] to read
`integritytab` early at boot and mount them in the system.  This will
crate `systemd-integritysetup`[23] units on demand.

One issue that I see is that this time there is no kernel command
line, so the keyfile cannot be send as a boot parameter.  In any case
seems to be upstream development to fetch the key from the TPM before
the unit can mount the device.

### Example

```bash
# Setup with keyed integrity
dd if=/dev/random bs=128 count=1 of=/etc/cryptsetup-keys.d/key

integritysetup format /dev/sda3 --integrity hmac-sha256 \
    --integrity-key-file=/etc/cryptsetup-keys.d/key \
    --integrity-key-size 128

integritysetup open /dev/sda3 test --integrity hmac-sha256 \
    --integrity-key-file=/etc/cryptsetup-keys.d/key \
    --integrity-key-size 128

mkfs.btrfs /dev/mapper/test
mount /dev/mapper/test /mnt
```

### Learn more

[20] https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-integrity.html
[21] https://www.freedesktop.org/software/systemd/man/integritytab.html
[22] https://www.freedesktop.org/software/systemd/man/systemd-integritysetup-generator.html
[23] https://www.freedesktop.org/software/systemd/man/systemd-integritysetup@.service.html


Btrfs integrity
---------------

Btrfs, natively, support data and metadata checksum[30] stored inside
the b-tree node header (for metadata), or inside the data block itself
(for data).

By default crc32c it is used, but can be changed since the kernel 5.5.
For example, XXHASH can improve security guarantess without relevant
performance impact.

In a running system, it can be checked the current checksum algorith
used and changed with:


- (WIP) If you didn't already, can you check how btrfs checksums interact with non-CoW? (I didn't read the content on confluence yet) 
https://btrfs.wiki.kernel.org/index.php/FAQ#Can_I_have_nodatacow_.28or_chattr_.2BC.29_but_still_have_checksumming.3F

That's also necessary for e.g. swapfile support, which is implemented
differently than one might expect. The kernel doesn't use the
filesystem driver for swapping at all, when enabling a swap file, the
kernel is told the range of blocks on the block device and it
reads/writes them directly



```bash
cat /sys/fs/btrfs/**/checksum
mkfs.btrfs --checksum xxhash /dev/sda3
```

### Learn more

[30] https://btrfs.readthedocs.io/en/latest/Checksumming.html


dm-crypto / LUKS2
-----------------

data authentication
btrfs

### Systemd

### Example

### Learn more
https://lists.gnu.org/archive/html/grub-devel/2022-02/msg00006.html

mkosi-initrd
------------
