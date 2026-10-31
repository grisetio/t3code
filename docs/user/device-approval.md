# Device approval

When an agent runs `sudo` on a Linux or macOS machine, you approve that one
command with your fingerprint in the T3 Code Android app instead of typing a
password. The phone shows the exact command, the working directory, and which
user it runs as. The agent's own explanation is labeled unverified, so judge
the command itself. Deny refuses it, and the agent is told not to retry.

## Set up

On the phone, open **Settings → Device approval** and choose **Set up** for the
machine. Setup asks for your fingerprint first, then the sudo password once.
Enter it, or choose **Use a terminal command instead** to get a command to paste
into a terminal on that machine. The password goes to the server once and is
never stored. Setup trusts your account on that machine, the same as typing the sudo
password into T3 Code: anything running as you, including an agent, could
change what it installs. On a Mac that uses Touch ID for `sudo`, a Touch ID
prompt may appear on the Mac first; Cancel continues with the password.

After setup, T3 Code runs a test `sudo` for you to approve on the phone. Run it
again any time with **Test** in **Settings → Device approval** on the phone,
web, or desktop.

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

Requests show up in the app as a banner, and in the agent's thread, while the
app is connected to the environment. With T3 Connect linked, the phone also
gets a push for requests that belong to a thread; without it there is no push.
Web and desktop show requests and can deny them; approving needs the phone.

## Remove a device or turn it off

In **Settings → Device approval**, open **Details**. **Revoke** removes another
phone. On a phone, **Remove this phone** removes that phone after a fingerprint
and deletes its key; other phones keep approving. If you lose a phone, revoke
it from another device or with the password; the password keeps working for
`sudo` in a terminal.

Once a phone is set up, adding a phone, revoking, and turning off are approved
on a phone by default. You can still use the sudo password instead; it passes
through the T3 Code server on its way to `sudo`.

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
