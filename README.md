The pam_seccomp PAM module can set up seccomp syscall filter for a session. 
It uses [Kafel](http://google.github.io/kafel) to describe policies, and compiled into BPF code that can be used by seccomp filter.

# Build
```
$ sudo apt install build-essential bison flex
$ cd pam_seccomp
$ make
```

# Usage
- Copy pam_seccomp.so to the PAM modules directory.
(/lib/x86_64-linux-gnu/security/ on debian stretch amd64)
- Add PAM config in /etc/pam.d
```
session required pam_seccomp.so debug policy=/etc/security/seccomp.d/sshd
```

- Add Policy config (/etc/security/seccomp.d/sshd)
```
POLICY sample {
	KILL {
		ptrace
	}
}

USE sample DEFAULT ALLOW
```
This configuration disables ptrace syscall for remote logined users.

