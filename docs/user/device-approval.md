# Device approval

When an agent runs `sudo` on a Linux or macOS machine, you approve that one
command with your fingerprint in the T3 Code Android app instead of typing a
password. The phone shows the exact command, the working directory, and which
user it runs as. The agent's own explanation is labeled unverified, so judge
the command itself. Deny refuses it, and the agent is told not to retry.

## Set up

On the phone, open **Settings → Device approval** and choose **Set up** for the
machine. Before it asks for anything, setup lists the files it will change on
that machine. It then asks for your fingerprint, then the sudo password once.
Enter it, or choose **Use a terminal command instead** to get a command to paste
into a terminal on that machine. The password goes to the server once and is
never stored. Setup trusts your account on that machine, the same as typing the sudo
password into T3 Code: anything running as you, including an agent, could
change what it installs. On a Mac that uses Touch ID for `sudo`, a Touch ID
prompt may appear on the Mac first; Cancel continues with the password.

Setup doesn't run a test `sudo`. The next `sudo` an agent runs asks on the
phone.

If the T3 Code build on that machine doesn't include the device approval
helper, **Set up** is unavailable and Settings says so.

To add another phone, choose **Add this phone** on it. Approve on a phone that
is already set up after checking that both show the same code, or enter the
password. Until a phone is set up, only the password can approve it.

## What changes

- Every agent `sudo` asks again. One approval covers one command.
- Your own `sudo` in a terminal then asks every time, because setup turns off
  sudo's few-minute credential cache for your user. It asks as before: the
  password on Linux, Touch ID or the password on macOS.
- Commands you run with `sudo` no longer get your `HOME`, `PATH`, or editor
  variables. They get root's home and sudo's standard `PATH`, and `visudo` uses
  the system editor. On macOS, a script that relies on Homebrew tools in your
  `PATH` needs their full path under `sudo`.
- `sudo` in T3 Code's terminal, and from anything T3 Code didn't start, asks the
  usual way, not the phone.
- A request nobody answers expires after about 100 seconds, and the command
  fails.
- Setup changes these files: the `sudo` PAM config (`/etc/pam.d/sudo_local` on
  macOS, `/etc/pam.d/sudo` on Linux), `/etc/sudoers.d/t3-elevation`, the
  approval config and phone keys in `/etc/t3-elevation`, and the helper and PAM
  module it copies to `/usr/local/lib`. **Turn off** restores them.

Requests show up in the app as a banner, and in the agent's thread, while the
app is connected to the environment. A request T3 Code can't match to a thread
waits at the top of the threads list instead. With T3 Connect linked, the phone also
gets a push for requests that belong to a thread; without it there is no push.
Web and desktop show requests and can deny them; approving needs the phone.

## Why the T3 Code server can't approve

- The phone creates its approval key in its secure hardware (StrongBox, or the
  TEE when there is none), and the key never leaves it. Every signature needs
  your fingerprint, and adding a fingerprint to the phone disables the key.
- At setup, the machine checks Android's proof that the key is hardware-backed,
  needs a fingerprint for every use, and belongs to the T3 Code app.
- The phone signs the exact command, user, and working directory it shows you.
  `sudo` checks that signature itself, as root, before anything runs.
- The T3 Code server only relays requests. It can delay, drop, or deny one, but
  it can't approve one, and neither can an agent running as you.

## Remove a device or turn it off

In **Settings → Device approval**, open **Details**. **Revoke** removes another
phone. On a phone, **Remove this phone** removes that phone after a fingerprint
and deletes its key; other phones keep approving. If you lose a phone, revoke
it from another device or with the password; the password keeps working for
`sudo` in a terminal.

If `sudo` on a Mac stops with "unable to initialize PAM", macOS's own
administrator prompt still runs a command as root:
`osascript -e 'do shell script "<command>" with administrator privileges'`.

Once a phone is set up, adding a phone and revoking are approved on a phone by
default. **Turn off** on web or desktop also asks a phone first; on the phone
itself it asks for the sudo password. You can always use the password instead;
it passes through the T3 Code server on its way to `sudo`.

**Turn off**, also under **Details**, restores the files T3 Code changed, and
agent `sudo` asks for the password again. When the setup comes from config
outside T3 Code, such as a Nix configuration, a rebuild would bring it back, so
**Turn off** opens a thread where an agent removes it from that config instead.

Enrolling a new fingerprint on the phone invalidates its key, and Settings shows
**Needs fixing**. **Fix** replaces the key with your fingerprint and the
password.

## Requirements

- An Android phone with Android 11 or later and a fingerprint sensor. iPhone
  isn't supported yet.
- The machine runs Linux or macOS. On Fedora and other SELinux systems, confined
  SELinux users aren't supported; setup says so, and `sudo` keeps asking for the
  password.
