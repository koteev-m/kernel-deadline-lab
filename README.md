# Kernel deadline lab

A manually dispatched capability check for a disposable offline x86-64 Ubuntu guest. One standard public Linux runner builds a guest with Canonical's signed archive metadata and the pinned Noble 6.8.0-48.48 kernel packages. KVM is required.

The guest boots with systemd and no network adapter. Its two synthetic veth endpoints exchange random UDP messages. An immutable 20-second boot-clock cutoff is compiled into a software traffic classifier at each transmitting end. A separate network namespace exercises a reversible nftables transaction. The runner observes guest reboot and ACPI suspend/wake over serial and QMP. A second serial boot must return the same disk challenge and report a new boot identifier. Output contains fixed test results, package versions and aggregate measurements. No raw identifiers, packet captures, image uploads, credentials, caches or artifacts are part of the workflow.

The nine checks cover KVM, guest ABI, PID 1, offline topology, classifier attachment, packet delivery across the cutoff, nftables isolation, reboot, and suspend. This is a short environment preflight.
