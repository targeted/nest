MAIN: nest

nest: *.c *.h
	gcc -o nest -O2 -Wall -lz variables.c utilities.c sha1dgst.c replay.c pkt_routines.c nest.c interface_routines.c debug_routines.c crypto.c bf_skey.c bf_enc.c

silent:
	gcc -DNO_SYSLOG -o nest -Os -Wall -lz variables.c utilities.c sha1dgst.c replay.c pkt_routines.c nest.c interface_routines.c debug_routines.c crypto.c bf_skey.c bf_enc.c

install:
	cp nest /usr/local/sbin/nest

clean:
	rm nest
