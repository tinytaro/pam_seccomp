.PHONY: clean

CFLAGS = -Wall -Ikafel/include -fPIC -shared
LDFLAGS = -lpam

all: pam_seccomp.so

pam_seccomp.so: pam_seccomp.c kafel/libkafel.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

kafel/libkafel.a:
	$(MAKE) -C kafel

clean:
	$(RM) pam_seccomp.so
	$(MAKE) -C kafel clean
