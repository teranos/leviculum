# lns(1)

## NAME

lns -- Reticulum network utility

## SYNOPSIS

**lns** [**-c** *dir*] [**-v**] *command* [*args*...]

## DESCRIPTION

**lns** is a multi-tool for interacting with a running Reticulum network. It combines the functionality of Python's **rnstatus**, **rnpath**, **rnprobe**, and more into a single binary.

## GLOBAL OPTIONS

**-c**, **--config** *dir*
:   Path to the Reticulum configuration directory.

**-v**, **--verbose**
:   Enable verbose logging.

## COMMANDS

### lns status

Show status of the Reticulum network. Connects to the running daemon via shared instance and displays transport information. Equivalent to Python's **rnstatus**.

### lns path [*destination*]

Show or request paths to destinations. Without an argument, lists all known paths. With a destination hash (hex), requests a path to that destination. Equivalent to Python's **rnpath**.

### lns probe *destination*

Probe a destination by sending a probe packet and measuring round-trip time. Equivalent to Python's **rnprobe**.

### lns interfaces

Show information about configured network interfaces.

### lns identity generate [**-o** *file*]

Generate a new Reticulum identity and write it to *file*.

### lns identity show *file*

Show the hash and public keys of the identity in *file*.

### lns cp [*options*] [*file*] [*destination*]

Copy files over Reticulum, compatible with Python's **rncp**. See **lncp**(1) for the full option reference.

### lns connect *addr*

Open an interactive session to a Reticulum daemon at *addr* (host:port). Supports link establishment, message exchange, and announce discovery. Type `/help` in the session for available commands.

### lns selftest *target* [*target*]

Run integration self-tests through one or two relay nodes. Tests link establishment, channel data, ratchet operation, and bulk transfer.

Options:

**--duration** *seconds*
:   Test duration (default: 180).

**--rate** *n*
:   Messages per second per direction (default: 1).

**--mode** *mode*
:   Which phases to run: all, link, packet, ratchet-basic, ratchet-enforced, bulk-transfer, ratchet-rotation (default: all).

## EXAMPLES

Show network status:

    lns status

Request a path:

    lns path a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

Probe a destination:

    lns probe a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

Generate a new identity:

    lns identity generate -o my_identity

## SEE ALSO

**lnsd**(1), **lncp**(1)
