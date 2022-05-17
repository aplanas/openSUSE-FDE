* Goals of the project
  + Protect intellectual property (IP)
  + IP can be present in the system (/usr), in user data (/var,
    /home), or even in initrd.
  + Loss or Theft: protect data from unauthorized access due to loss
    or theft of the device
  + Disk Lifecycle: since you cannot really destroy data on a SSD,
    encrypt everything secured with a TPM chip, so that the data
    cannot be recovered after EoL.
  + The encryption key should be sealed by the TPM (high priority:
    cloud and server room scenario) and / or a FIDO2 key (medium
    priority: desktop / laptop use case when we want to protect from
    stealing)

* Possible solutions analyzed
  + Grub2 + TPM2 patch[1] from Microsoft.
    - This will use a PCR and / or a NVI entry to unseal a LUKS2
      enrolled key
    - Encrypt all the data (kernel, initrd, /usr, /home, ...)
    - High dependency of Grub2
    - High performance penalty, as /usr is included and there is no
      direct way of avoiding this
    - FIDO2 cannot be included
    - Argon2 key derivation family for LUKS2 cannot be included
      (unless we hack something like was done by a Debian maintainer,
      but very costly on maintenance)
    - Seems that will be required by Microsoft Azure
    - The kernel command line / kernel / initrd are not measured. Do
      not protect against a Cloud provider that allows the re-use of
      VMs from other users.  This AFAIU is a variation of the evil
      maiden attack, where someone can turn on the laptop and change
      the kernel command line to have full access.
    - The order seems to be: Grub2 unseal the LUKS2 key, open the
      device, read the configuration file to show the menu.  This is
      good as will be OK with manual and automatic rollbacks.
    - No clear way of recovering. What to do when some PCR changed in
      a non-predicted way.
    - Do not mix properly with measured boot, as the safest
      implementation will use PCR7 almost only, that is the one that
      represent when Secure Boot has been used and all the
      certificates are the ones expected.

  + systemd-cryptenroll + (TPM2 + FIDO2) + rest of the systemd utils
    - The EFI partition (ESP) is unencrypted, and it is there where
      the kernel and the initrd are living.
    - Better integration with measured boot.  The boot chain is
      measured, including the boot loader, kernel command line, boot
      loader config, kernel and initrd.
    - Besides PCR7 we can use other PCRs to unseal where /usr, /etc,
      /var and the rest of the system is living.
    - Is a more flexible solution: can be made to not depend on the
      boot loader, /usr can be (later) set unencrypted (if data
      authentication for unencrypted volumes in btrfs is resolved).
    - Cover the server room case (TPM), and the stolen laptop case
      (FIDO).
    - If the initrd contains a secret, this can be solved later with
      system-sysext.
    - There is a recovery process implemented when the PCR values are
      not matching.

* A sub-team evaluate systemd was a better approach
  + Is more flexible, so is possible to set a road from a MVP to a
    final enterprise solution, without throwing away all the work
    done.  For example, if we go for the Grub2 solution:
    - How can we let /usr open if we see a big performance penalty?
    - How can we move it in a way that we can integrate a FIDO2 key to
      address the Laptop use case?
    - What recovery policies can be implemented for the client when
      the registered TPM policy somehow do not unseal the device?
    - Grub2 upstream team is small (single maintainer), and this is
      perceived as big risk inside the team.
    - There is a movement in Tumbleweed to move to systemd-boot
      eventually, as is a more simple model for a bootloader.

* Work done so far or WIP (that I am aware)
  + Exploration and analysis of alternatives[2] (lnussel)
  + Preparations for systemd-boot[3] (lnussel)
    - We should design a solution as most agnostic of the bootloader
      as possible.  Grub2 (with a patch) and systemd-boot are
      supporting the boot loader specification[4], and we are moving
      the solution under this layout.
    - Work done to support secure boot, SBAT and other features
      (tracked under several bsc / boo numbers)
  + Initial research about how to solve the transactional-update
    rollback with FDE (lnussel)
    - The EFI have room for several kernels and initrd.
    - With FDE the kernel is living in the encrypted volume, should be
      extracted from there in some cases before a rollback is
      possible.
    - For one kernel we can have multiple initrd (a package, as today,
      can trigger the initrd creation after an update), and can be of
      use for multiple snapshots.  This is the 1:N:M problem, and
      somehow we need to serialize it in grub menu entries /
      systemd-boot files.  Each one will have its how kernel command
      line.
    - Another solution is to use an unified kernel image (kernel +
      initrd + command line) signed, and duplicate space when a new
      command line is required (to point to a new snapshot)
    - WIP

   + TPM PCR value prediction (fvogt)
     - There is a Python script (now updated for openSUSE / SUSE use
       case) that can be used to predict the new PCR values for the
       next boot.
     - Fabian expect to rewrite it in C and maybe integrate it into
       systemd.
     - The complicated part is PCR8, for the Grub config execution
       path.  There are some heuristics that can help is many of the
       situations.
     - systemd-cryptenroll do not have a parameter to indicate the PCR
       values expected for the next boot, only the current PCR index.
       Some one should implement it.
     - In the same way, systemd-cryptenroll developers are expecting
       someone to implement the PCR brittle solution present for TPM2,
       where a policy is created to indicate the PCR index, and a
       signed file is later referenced that will contain the PCR
       values.  Now the TPM can unseal under those values (that can be
       different each time) always that the signed file is validated.
   + Re-integrate grub-tpm.efi into grub.efi (fvogt / mchang)
     - To measure kernel cmd line and configuration we need to replace
       grub.efi with grub-tpm.efi.
     - The code should be the same, and if the TPM is present and
       enabled, do the measurement.
     - A bsc tracked this issue, and now grub has been unified

   + Research about dm-{verity, integrity, crypto} and LUKS2 (aplanas)
     - Published a WIP document with the findings[5]
     - It should be moved ASAP to git or any other open place for
       public discussion
     - Include analysis for systemd integration for each component
     - Identification of a big missing component in our stack: data
       authentication
   + Performance measurement for encrypted devices (aplanas)
     - Very big performance impact due to many circumstances (LUKS2
       encryption algorithm, journaling for btrfs, block size,
       dm-integrity layering, etc)
     - Strongly suggest to have unencrypted /usr
     - WIP explore better the space and create a table of performance
       penalty for each configuration
   + Data authentication (aplanas)
     - We do not have any mechanism to detect changes in the data
       (clean nor encrypted)
     - Implement AEAD data authentication for LUKS2 in
       libstorage-ng[6]
     - With aegis128-random we only cover encrypted data.
     - Real evaluation with off-line modifications of data
       authenticated and non-data authenticated encrypted volumes
   + Rebase btrfs patches[7] to support keyed (indirectly via TPM)
     data authentication for data and metadata hashes (aplanas)
     - Very much WIP
     - The performance penalty should be very low (only below a merkle
       tree a-la dm-verity). This can be a valid trade-off.
   + Research dm-integrity with keyed hash for unencrypted /usr
     (aplanas)
     - Is an alternative for btrfs subvolumes in case that the patch
       is not good for the job.
     - The performance penalty should be higher, but still better that
       the encryption.

  + Manual integration of systemd-cryptenroll in openSUSE[8] (antonio)
    - Done before the workshop

* Proposed roadmap
  + This has not been agreed, so this is only my own opinion (aplanas)

  + Stage 1 (MVP)
    - Grub2 as it is today
    - No boot loader specification layout in ESP
    - Clean boot partition and FDE for the rest
    - Implement the steps from [8] inside YaST
    - Enable data authentication in the encrypted volume
    - initrd creation from the FDE side
    - Use an in-house tool to predict the PCRs 4, 5, 7, 8 and 9

  + Stage 2 (Complete solution)
    - Add bootloader specification patch to grub2
    - Update YaST to deploy the ESP under this layout
    - Include the new rollback code for the new ESP layout
    - Use dm-integrity with keyed hash from a TPM for an unencrypted /usr
    - Use systemd-sysext, mkosi and a local signature to create initrd
      extensions for drivers where IP is relevant

  + Stage 3..n (Full systemd alignment)
    - Work in an upstream solution for PCR prediction for systemd
    - Work in an upstream solution for future PCR sealing for systemd
    - Work in an upstream solution for brittle PCR for systemd
    - Work on the btrfs patch and decide if discard it or improve it,
      and involve the btrfs developers
    - Use the systemd code for PCRs if / when available
    - Drop grub2 in Tumbleweed and move to systemd-boot

* References

[1] https://lists.gnu.org/archive/html/grub-devel/2022-02/msg00006.html

[2] http://w3.suse.de/~lnussel/FDE-plan.svg

[3] https://en.opensuse.org/Systemd-boot

[4] https://systemd.io/BOOT_LOADER_SPECIFICATION/

[5] https://confluence.suse.com/display/systembootinit/An+brief+introduction+about+dm-%7Bverity%2C+integrity%2C+crypt%7D+and+LUKS2

[6] https://github.com/openSUSE/libstorage-ng/pull/870

[7] https://lwn.net/ml/linux-fsdevel/20200428105859.4719-1-jth@kernel.org/

[8] https://en.opensuse.org/SDB:LUKS2,_TPM2_and_FIDO2
