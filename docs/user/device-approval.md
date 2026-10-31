# Device approval

When an agent runs `sudo` on a Linux or macOS machine, you approve that one
command with your fingerprint in the T3 Code Android app instead of typing a
password. The phone shows the exact command, the working directory, and which
user it runs as. The agent's own explanation is labeled unverified, so judge
the command itself. Deny refuses it, and the agent is told not to retry.

## Set up

On the phone, open **Settings → Device approval** and choose **Set up on this
machine** for the environment. Setup lists the system files it will change.
Enter the sudo password once, or leave it empty to get a command to paste into
a terminal on that machine. The password goes to the server once and is never
stored.

After setup, T3 Code runs a test `sudo` for you to approve on the phone. Run it
again any time with **Test** in **Settings → Device approval** on the phone,
web, or desktop.

To add another phone, choose **Add this phone** on it. Approve on a phone that
is already set up after checking that both show the same code, or enter the
password.

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

In **Settings → Device approval**, **Revoke** removes a phone. On the phone
itself, **Remove this device** also deletes its key. If you lose a phone, revoke
it from another device or with the password; the password keeps working for
`sudo` in a terminal.

**Turn off** restores the files T3 Code changed, and agent `sudo` asks for the
password again. Parts set up outside T3 Code stay in place, and Settings says
so.

Enrolling a new fingerprint on the phone invalidates its key. Choose **Set up
this phone again** to replace it.

## Requirements

- An Android phone with Android 11 or later and a fingerprint sensor. iPhone
  isn't supported yet.
- The machine runs Linux or macOS. On Fedora and other SELinux systems, confined
  SELinux users aren't supported; setup says so, and `sudo` keeps asking for the
  password.
