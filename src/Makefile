# Don't edit Makefile!  Use conf-* for configuration.

SHELL=/bin/sh

default: it

clean:
	rm -f alloc.o alloc_re.o auto-str auto-str.o auto_cadir.c auto_cadir.o \
	auto_cafile.c auto_cafile.o auto_ccafile.c auto_ccafile.o \
	auto_certchainfile.c auto_certchainfile.o \
	auto_certfile.c auto_certfile.o auto_ciphers.c auto_ciphers.o \
	auto_dhfile.c auto_dhfile.o auto_keyfile.c auto_keyfile.o buffer.o \
	buffer_0.o buffer_1.o buffer_2.o buffer_copy.o buffer_get.o buffer_put.o \
	buffer_read.o buffer_write.o byte_chr.o byte_copy.o byte_cr.o \
	byte_diff.o byte_zero.o case_diffb.o case_diffs.o ccperl cdb.a cdb.o \
	cdb_hash.o cdb_make.o chkshsgr chkshsgr.o choose coe.o compile dns_name.o \
	env.o error.o error_str.o \
	fd_copy.o fd_move.o fmt_ulong.o getln.o getln2.o hasflock.h hassgact.h \
	hassgprm.h hasshsgr.h haswaitp.h https@ iopause.h iopause.o ip_fmt.o \
	it it-base it-sslperl load lock_ex.o lock_un.o makelib \
	ndelay_off.o ndelay_on.o open_append.o open_read.o open_trunc.o \
	openreadclose.o pathexec_env.o pathexec_run.o perlembed.lib prot.o \
	readclose.o remoteinfo.o rules.o scan_uint.o scan_ulong.o seek_set.o \
	select.h sgetopt.o sig.o sig_block.o sig_catch.o sig_pause.o socket.lib \
	socket_accept.o socket_bind.o socket_conn.o socket_delay.o \
	socket_listen.o socket_local.o socket_opts.o socket_remote.o \
	socket_tcp.o ucspissl.a ucspissl.o ssl_ca.o ssl_cca.o ssl_certkey.o \	
	ssl_chainfile.o \
	ssl_ciphers.o ssl_context.o ssl_env.o ssl_error.o ssl_io.o ssl_new.o \
	ssl_params.o ssl_timeoutaccept.o ssl_timeoutconn.o ssl_verify.o sslcat \
	sslclient sslclient.o sslconnect sslhandle.o sslperl sslperl.o sslprint \
	sslprint.o sslserver sslserver.o str_chr.o str_diff.o str_len.o \
	str_start.o stralloc_cat.o stralloc_catb.o stralloc_cats.o \
	stralloc_copy.o stralloc_eady.o stralloc_opyb.o stralloc_opys.o \
	stralloc_pend.o strerr_die.o strerr_sys.o subgetopt.o sysdeps systype \
	tai_pack.o taia_add.o taia_approx.o taia_frac.o taia_less.o taia_now.o \
	taia_pack.o taia_sub.o taia_uint.o timeoutconn.o uint16_pack.o \
	uint16_unpack.o uint32.h uint32_pack.o uint32_unpack.o uint64.h unix.a \
	wait_nohang.o wait_pid.o

alloc.o: compile alloc.c alloc.h error.h
	./compile alloc.c

alloc_re.o: compile alloc_re.c alloc.h byte.h
	./compile alloc_re.c

auto-str: load auto-str.o unix.a
	./load auto-str unix.a 

auto-str.o: compile auto-str.c buffer.h exit.h
	./compile auto-str.c

auto_cadir.c: auto-str conf-cadir
	./auto-str auto_cadir "`head -1 conf-cadir`" > auto_cadir.c

auto_cadir.o: compile auto_cadir.c
	./compile auto_cadir.c

auto_cafile.c: auto-str conf-cafile
	./auto-str auto_cafile "`head -1 conf-cafile`" > auto_cafile.c

auto_cafile.o: compile auto_cafile.c
	./compile auto_cafile.c

auto_ccafile.c: auto-str conf-ccafile
	./auto-str auto_ccafile "`head -1 conf-ccafile`" > auto_ccafile.c

auto_ccafile.o: compile auto_ccafile.c
	./compile auto_ccafile.c

auto_certchainfile.c: auto-str conf-certchainfile
	./auto-str auto_certchainfile "`head -1 conf-certchainfile`" > auto_certchainfile.c
  
auto_certchainfile.o: compile auto_certchainfile.c
	./compile auto_certchainfile.c

auto_certfile.c: auto-str conf-certfile
	./auto-str auto_certfile "`head -1 conf-certfile`" > auto_certfile.c

auto_certfile.o: compile auto_certfile.c
	./compile auto_certfile.c

auto_ciphers.c: auto-str conf-ciphers
	./auto-str auto_ciphers "`head -1 conf-ciphers`" > auto_ciphers.c

auto_ciphers.o: compile auto_ciphers.c
	./compile auto_ciphers.c

auto_dhfile.c: auto-str conf-dhfile
	./auto-str auto_dhfile "`head -1 conf-dhfile`" > auto_dhfile.c

auto_dhfile.o: compile auto_dhfile.c
	./compile auto_dhfile.c

auto_keyfile.c: auto-str conf-keyfile
	./auto-str auto_keyfile "`head -1 conf-keyfile`" > auto_keyfile.c

auto_keyfile.o: compile auto_keyfile.c
	./compile auto_keyfile.c

buffer.o: compile buffer.c buffer.h
	./compile buffer.c

buffer_0.o: compile buffer_0.c buffer.h
	./compile buffer_0.c

buffer_1.o: compile buffer_1.c buffer.h
	./compile buffer_1.c

buffer_2.o: compile buffer_2.c buffer.h
	./compile buffer_2.c

buffer_copy.o: compile buffer_copy.c buffer.h
	./compile buffer_copy.c

buffer_get.o: compile buffer_get.c buffer.h byte.h error.h
	./compile buffer_get.c

buffer_put.o: compile buffer_put.c buffer.h str.h byte.h error.h
	./compile buffer_put.c

buffer_read.o: compile buffer_read.c buffer.h
	./compile buffer_read.c

buffer_write.o: compile buffer_write.c buffer.h
	./compile buffer_write.c

byte_chr.o: compile byte_chr.c byte.h
	./compile byte_chr.c

byte_copy.o: compile byte_copy.c byte.h
	./compile byte_copy.c

byte_cr.o: compile byte_cr.c byte.h
	./compile byte_cr.c

byte_diff.o: compile byte_diff.c byte.h
	./compile byte_diff.c

byte_zero.o: compile byte_zero.c byte.h
	./compile byte_zero.c

case_diffb.o: compile case_diffb.c case.h
	./compile case_diffb.c

case_diffs.o: compile case_diffs.c case.h
	./compile case_diffs.c

ccperl: conf-ccperl conf-perl print-ccperl.sh
	rm -f ccperl
	sh print-ccperl.sh > ccperl

cdb.a: makelib cdb.o cdb_hash.o cdb_make.o
	./makelib cdb.a cdb.o cdb_hash.o cdb_make.o

cdb.o: compile cdb.c error.h seek.h byte.h cdb.h uint32.h
	./compile cdb.c

cdb_hash.o: compile cdb_hash.c cdb.h uint32.h
	./compile cdb_hash.c

cdb_make.o: compile cdb_make.c seek.h error.h alloc.h cdb.h cdb_make.h \
uint32.h buffer.h uint32.h
	./compile cdb_make.c

chkshsgr: load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: compile chkshsgr.c exit.h
	./compile chkshsgr.c

choose: home warn-auto.sh choose.sh
	rm -f choose
	cat warn-auto.sh choose.sh \
	| sed s}HOME}"`head -1 home`"}g \
	> choose
	chmod 755 choose

coe.o: compile coe.c coe.h
	./compile coe.c

compile: conf-cc conf-ssl print-cc.sh systype warn-auto.sh
	rm -f compile
	sh print-cc.sh > compile
	chmod 755 compile

dns_name.o: compile dns_name.c stralloc.h ip.h str.h
	./compile dns_name.c

env.o: compile env.c str.h env.h
	./compile env.c

error.o: compile error.c error.h
	./compile error.c

error_str.o: compile error_str.c error.h
	./compile error_str.c

fd_copy.o: compile fd_copy.c fd.h
	./compile fd_copy.c

fd_move.o: compile fd_move.c fd.h
	./compile fd_move.c

fmt_ulong.o: compile fmt_ulong.c fmt.h
	./compile fmt_ulong.c

getln.o: compile getln.c byte.h getln.h buffer.h stralloc.h gen_alloc.h
	./compile getln.c

getln2.o: compile getln2.c byte.h getln.h buffer.h stralloc.h gen_alloc.h
	./compile getln2.c

hasflock.h: choose compile load tryflock.c hasflock.h1 hasflock.h2
	./choose cl tryflock hasflock.h1 hasflock.h2 > hasflock.h

hassgact.h: choose compile trysgact.c hassgact.h1 hassgact.h2
	./choose cl trysgact hassgact.h1 hassgact.h2 > hassgact.h

hassgprm.h: choose compile trysgprm.c hassgprm.h1 hassgprm.h2
	./choose cl trysgprm hassgprm.h1 hassgprm.h2 > hassgprm.h

hasshsgr.h: choose compile tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr \
warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

haswaitp.h: choose compile load trywaitp.c haswaitp.h1 haswaitp.h2
	./choose cl trywaitp haswaitp.h1 haswaitp.h2 >haswaitp.h

https@: home warn-auto.sh https@.sh
	rm -f https@
	cat warn-auto.sh https@.sh \
	| sed s}HOME}"`head -1 home`"}g \
	| sed s}TCPBIN}"`head -1 conf-tcpbin`"}g \
	> https@
	chmod 755 https@

iopause.h: choose compile load trypoll.c iopause.h1 iopause.h2
	./choose clr trypoll iopause.h1 iopause.h2 >iopause.h

iopause.o: compile iopause.c taia.h select.h iopause.h tai.h taia.h \
uint64.h tai.h uint64.h
	./compile iopause.c

ip_fmt.o: compile ip_fmt.c stralloc.h ip.h str.h
	./compile ip_fmt.c

ip4_bit.o: \
compile ip4_bit.c ip4_bit.h byte.h scan.h fmt.h str.h
	./compile ip4_bit.c

it: it-base it-sslperl sysdeps

it-base: sslclient sslserver https@ sslcat sslconnect sslprint sysdeps

it-sslperl: sslperl sysdeps

load: conf-ld print-ld.sh systype warn-auto.sh
	rm -f load
	sh print-ld.sh > load
	chmod 755 load

lock_ex.o: compile lock_ex.c hasflock.h lock.h
	./compile lock_ex.c

lock_un.o: compile lock_un.c hasflock.h lock.h
	./compile lock_un.c

makelib: print-ar.sh systype warn-auto.sh
	rm -f makelib
	sh print-ar.sh > makelib
	chmod 755 makelib

ndelay_off.o: compile ndelay_off.c ndelay.h
	./compile ndelay_off.c

ndelay_on.o: compile ndelay_on.c ndelay.h
	./compile ndelay_on.c

open_append.o: compile open_append.c open.h
	./compile open_append.c

open_read.o: compile open_read.c open.h
	./compile open_read.c

open_trunc.o: compile open_trunc.c open.h
	./compile open_trunc.c

openreadclose.o: compile openreadclose.c error.h open.h readclose.h \
openreadclose.h stralloc.h stralloc.h gen_alloc.h gen_alloc.h
	./compile openreadclose.c

pathexec_env.o: compile pathexec_env.c stralloc.h alloc.h str.h byte.h \
env.h pathexec.h gen_alloc.h
	./compile pathexec_env.c

pathexec_run.o: compile pathexec_run.c error.h stralloc.h str.h env.h \
pathexec.h gen_alloc.h
	./compile pathexec_run.c

perlembed.lib: conf-perl conf-ldperl print-perlembed.sh
	rm -f perlembed.lib
	sh print-ldperl.sh > perlembed.lib

prot.o: compile prot.c prot.h
	./compile prot.c

readclose.o: compile readclose.c error.h readclose.h stralloc.h \
gen_alloc.h
	./compile readclose.c

remoteinfo.o: compile remoteinfo.c fmt.h buffer.h socket.h error.h ip.h \
iopause.h timeoutconn.h remoteinfo.h uint16.h taia.h uint16.h stralloc.h \
uint16.h tai.h gen_alloc.h uint64.h
	./compile remoteinfo.c

rules.o: compile rules.c alloc.h stralloc.h open.h cdb.h rules.h ip.h \
gen_alloc.h uint32.h stralloc.h gen_alloc.h ip4_bit.h
	./compile rules.c

scan_uint.o: compile scan_uint.c scan.h
	./compile scan_uint.c

scan_ulong.o: compile scan_ulong.c scan.h
	./compile scan_ulong.c

seek_set.o: compile seek_set.c seek.h
	./compile seek_set.c

select.h: choose compile trysysel.c select.h1 select.h2
	./choose c trysysel select.h1 select.h2 > select.h

sgetopt.o: compile sgetopt.c buffer.h sgetopt.h subgetopt.h subgetopt.h
	./compile sgetopt.c

sig.o: compile sig.c sig.h
	./compile sig.c

sig_block.o: compile sig_block.c sig.h hassgprm.h
	./compile sig_block.c

sig_catch.o: compile sig_catch.c sig.h hassgact.h
	./compile sig_catch.c

sig_pause.o: compile sig_pause.c sig.h hassgprm.h
	./compile sig_pause.c

socket.lib: trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

socket_accept.o: compile socket_accept.c byte.h socket.h uint16.h ip.h stralloc.h
	./compile socket_accept.c

socket_bind.o: compile socket_bind.c byte.h socket.h uint16.h ip.h stralloc.h
	./compile socket_bind.c

socket_conn.o: compile socket_conn.c byte.h socket.h uint16.h ip.h stralloc.h
	./compile socket_conn.c

socket_delay.o: compile socket_delay.c socket.h uint16.h ip.h stralloc.h
	./compile socket_delay.c

socket_listen.o: compile socket_listen.c socket.h uint16.h ip.h stralloc.h
	./compile socket_listen.c

socket_local.o: compile socket_local.c byte.h socket.h uint16.h ip.h stralloc.h
	./compile socket_local.c

socket_opts.o: compile socket_opts.c socket.h uint16.h ip.h stralloc.h
	./compile socket_opts.c

socket_remote.o: compile socket_remote.c byte.h socket.h uint16.h ip.h stralloc.h
	./compile socket_remote.c

socket_tcp.o: compile socket_tcp.c ndelay.h socket.h uint16.h ip.h stralloc.h
	./compile socket_tcp.c

ssl_ca.o: compile ssl_ca.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_ca.c

ssl_cca.o: compile ssl_cca.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_cca.c

ssl_chainfile.o: compile ssl_chainfile.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_chainfile.c

ssl_certkey.o: compile ssl_certkey.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_certkey.c

ssl_ciphers.o: compile ssl_ciphers.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_ciphers.c

ssl_context.o: compile ssl_context.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_context.c

ssl_env.o: compile ssl_env.c fmt.h pathexec.h ucspissl.h stralloc.h str.h \
stralloc.h gen_alloc.h gen_alloc.h
	./compile ssl_env.c

ssl_error.o: compile ssl_error.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_error.c

ssl_io.o: compile ssl_io.c iopause.h buffer.h taia.h ucspissl.h strerr.h \
error.h sig.h taia.h tai.h stralloc.h tai.h uint64.h gen_alloc.h uint64.h
	./compile ssl_io.c

ssl_new.o: compile ssl_new.c ucspissl.h ndelay.h stralloc.h gen_alloc.h
	./compile ssl_new.c

ssl_params.o: compile ssl_params.c ucspissl.h stralloc.h gen_alloc.h
	./compile ssl_params.c

ssl_timeoutaccept.o: compile ssl_timeoutaccept.c ucspissl.h iopause.h error.h \
stralloc.h taia.h gen_alloc.h tai.h uint64.h
	./compile ssl_timeoutaccept.c

ssl_timeoutconn.o: compile ssl_timeoutconn.c ucspissl.h iopause.h error.h \
stralloc.h taia.h gen_alloc.h tai.h uint64.h
	./compile ssl_timeoutconn.c

ssl_verify.o: compile ssl_verify.c ucspissl.h case.h strerr.h stralloc.h \
gen_alloc.h
	./compile ssl_verify.c

sslcat: home warn-auto.sh sslcat.sh
	rm -f sslcat
	cat warn-auto.sh sslcat.sh \
	| sed s}HOME}"`head -1 home`"}g \
	> sslcat
	chmod 755 sslcat

sslclient: load sslclient.o remoteinfo.o timeoutconn.o ucspissl.a unix.a \
auto_cafile.o auto_cadir.o auto_ciphers.o socket.lib ssl.lib
	./load sslclient remoteinfo.o timeoutconn.o ucspissl.a unix.a \
	auto_cafile.o auto_cadir.o auto_ciphers.o \
	`cat socket.lib` `cat ssl.lib`

sslclient.o: compile sslclient.c ucspissl.h sig.h exit.h sgetopt.h uint16.h uint64.h \
fmt.h scan.h str.h ip.h socket.h fd.h stralloc.h buffer.h tai.h taia.h \
getln.h error.h strerr.h pathexec.h timeoutconn.h remoteinfo.h iopause.h \
auto_cafile.h auto_cadir.h auto_ciphers.h \
byte.h ndelay.h wait.h subgetopt.h gen_alloc.h buffer.h stralloc.h
	./compile sslclient.c

sslconnect: home warn-auto.sh sslconnect.sh
	rm -f sslconnect
	cat warn-auto.sh sslconnect.sh \
	| sed s}HOME}"`head -1 home`"}g \
	| sed s}TCPBIN}"`head -1 conf-tcpbin`"}g \
	> sslconnect
	chmod 755 sslconnect

sslhandle.o: compile sslhandle.c ucspissl.h uint16.h str.h byte.h fmt.h scan.h \
ip.h fd.h exit.h env.h prot.h open.h wait.h stralloc.h alloc.h buffer.h \
getln.h error.h strerr.h sgetopt.h socket.h ndelay.h remoteinfo.h rules.h \
sig.h auto_cafile.h auto_cadir.h auto_ccafile.h auto_dhfile.h auto_certchainfile.h \
auto_certfile.h auto_keyfile.h auto_ciphers.h iopause.h coe.h lock.h \
stralloc.h gen_alloc.h buffer.h stralloc.h subgetopt.h uint16.h \
stralloc.h uint16.h stralloc.h stralloc.h iopause.h taia.h taia.h \
gen_alloc.h gen_alloc.h gen_alloc.h gen_alloc.h gen_alloc.h taia.h tai.h \
tai.h tai.h uint64.h uint64.h uint64.h
	./compile sslhandle.c

sslperl: load sslperl.o auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_dhfile.o auto_certfile.o auto_keyfile.o auto_ciphers.o auto_certchainfile.o \
rules.o ip4_bit.o remoteinfo.o timeoutconn.o sslhandle.o cdb.a ucspissl.a unix.a cdb.a unix.a \
socket.lib ssl.lib socket.lib perlembed.lib
	./load sslperl auto_cafile.o auto_ccafile.o auto_cadir.o auto_dhfile.o \
	auto_certfile.o auto_keyfile.o auto_ciphers.o auto_certchainfile.o \
	rules.o ip4_bit.o remoteinfo.o \
	timeoutconn.o sslhandle.o cdb.a ucspissl.a unix.a cdb.a unix.a  `cat \
	socket.lib` `cat ssl.lib` `cat socket.lib` `cat perlembed.lib`

sslperl.o: compile ccperl sslperl.c strerr.h stralloc.h str.h gen_alloc.h
	./compile `cat ccperl` sslperl.c

sslprint: load sslprint.o auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_dhfile.o auto_certfile.o auto_keyfile.o auto_ciphers.o auto_certchainfile.o \
remoteinfo.o timeoutconn.o sslhandle.o cdb.a ucspissl.a unix.a cdb.a unix.a rules.o ip4_bit.o \
socket.lib ssl.lib socket.lib
	./load sslprint auto_cafile.o auto_ccafile.o auto_cadir.o auto_dhfile.o \
	auto_certfile.o auto_keyfile.o auto_ciphers.o auto_certchainfile.o \
	rules.o ip4_bit.o remoteinfo.o timeoutconn.o sslhandle.o cdb.a ucspissl.a unix.a cdb.a unix.a \
	`cat socket.lib` `cat ssl.lib` `cat socket.lib`

sslprint.o: compile sslprint.c buffer.h env.h
	./compile sslprint.c

sslserver: load sslserver.o auto_cafile.o auto_ccafile.o auto_cadir.o \
auto_certchainfile.o auto_dhfile.o auto_certfile.o auto_keyfile.o auto_ciphers.o \
rules.o ip4_bit.o remoteinfo.o timeoutconn.o cdb.a ucspissl.a unix.a socket.lib ssl.lib
	./load sslserver auto_cafile.o auto_ccafile.o auto_cadir.o auto_dhfile.o \
	auto_certchainfile.o auto_certfile.o auto_keyfile.o auto_ciphers.o \
	rules.o ip4_bit.o remoteinfo.o timeoutconn.o cdb.a ucspissl.a unix.a \
	`cat socket.lib` `cat ssl.lib`

sslserver.o: compile sslserver.c ucspissl.h uint16.h str.h byte.h fmt.h scan.h \
ip.h fd.h exit.h env.h prot.h open.h wait.h stralloc.h alloc.h buffer.h \
getln.h error.h strerr.h sgetopt.h pathexec.h socket.h ndelay.h \
remoteinfo.h rules.h sig.h auto_cafile.h auto_cadir.h auto_certchainfile.h \
auto_ccafile.h auto_dhfile.h auto_certfile.h auto_keyfile.h auto_ciphers.h \
stralloc.h gen_alloc.h buffer.h stralloc.h subgetopt.h iopause.h taia.h tai.h 
	./compile sslserver.c

str_chr.o: compile str_chr.c str.h
	./compile str_chr.c

str_diff.o: compile str_diff.c str.h
	./compile str_diff.c

str_len.o: compile str_len.c str.h
	./compile str_len.c

str_start.o: compile str_start.c str.h
	./compile str_start.c

stralloc_cat.o: compile stralloc_cat.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_cat.c

stralloc_catb.o: compile stralloc_catb.c stralloc.h byte.h gen_alloc.h
	./compile stralloc_catb.c

stralloc_cats.o: compile stralloc_cats.c byte.h str.h stralloc.h \
gen_alloc.h
	./compile stralloc_cats.c

stralloc_copy.o: compile stralloc_copy.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_copy.c

stralloc_eady.o: compile stralloc_eady.c alloc.h stralloc.h \
gen_allocdefs.h gen_alloc.h
	./compile stralloc_eady.c

stralloc_opyb.o: compile stralloc_opyb.c stralloc.h byte.h gen_alloc.h
	./compile stralloc_opyb.c

stralloc_opys.o: compile stralloc_opys.c byte.h str.h stralloc.h \
gen_alloc.h
	./compile stralloc_opys.c

stralloc_pend.o: compile stralloc_pend.c alloc.h stralloc.h \
gen_allocdefs.h gen_alloc.h
	./compile stralloc_pend.c

strerr_die.o: compile strerr_die.c buffer.h exit.h strerr.h
	./compile strerr_die.c

strerr_sys.o: compile strerr_sys.c error.h strerr.h
	./compile strerr_sys.c

subgetopt.o: compile subgetopt.c subgetopt.h
	./compile subgetopt.c

sysdeps: systype compile load hasflock.h hassgact.h hassgprm.h \
haswaitp.h iopause.h select.h uint64.h
	rm -f sysdeps
	cat systype compile load >> sysdeps
	grep sysdep hasflock.h >> sysdeps
	grep sysdep hassgact.h >> sysdeps
	grep sysdep hassgprm.h >> sysdeps
	grep sysdep haswaitp.h >> sysdeps
	grep sysdep iopause.h >> sysdeps
	grep sysdep select.h >> sysdeps
	grep sysdep uint64.h >> sysdeps

systype: find-systype.sh trycpp.c x86cpuid.c
	sh find-systype.sh > systype

tai_pack.o: compile tai_pack.c tai.h uint64.h
	./compile tai_pack.c

taia_add.o: compile taia_add.c taia.h tai.h uint64.h
	./compile taia_add.c

taia_approx.o: compile taia_approx.c taia.h tai.h uint64.h
	./compile taia_approx.c

taia_frac.o: compile taia_frac.c taia.h tai.h uint64.h
	./compile taia_frac.c

taia_less.o: compile taia_less.c taia.h tai.h uint64.h
	./compile taia_less.c

taia_now.o: compile taia_now.c taia.h tai.h uint64.h
	./compile taia_now.c

taia_pack.o: compile taia_pack.c taia.h tai.h uint64.h
	./compile taia_pack.c

taia_sub.o: compile taia_sub.c taia.h tai.h uint64.h
	./compile taia_sub.c

taia_uint.o: compile taia_uint.c taia.h tai.h uint64.h
	./compile taia_uint.c

timeoutconn.o: compile timeoutconn.c ndelay.h socket.h iopause.h error.h \
timeoutconn.h uint16.h taia.h uint16.h tai.h uint64.h ip.h stralloc.h
	./compile timeoutconn.c

ucspissl.a: makelib ucspissl.o ssl_io.o ssl_context.o ssl_new.o ssl_timeoutconn.o \
ssl_timeoutaccept.o ssl_certkey.o ssl_ca.o ssl_cca.o ssl_ciphers.o ssl_chainfile.o \
ssl_verify.o ssl_params.o ssl_error.o ssl_env.o
	./makelib ucspissl.a ucspissl.o ssl_io.o ssl_context.o ssl_new.o ssl_timeoutconn.o \
	ssl_timeoutaccept.o ssl_certkey.o ssl_ca.o ssl_cca.o ssl_ciphers.o ssl_chainfile.o \
	ssl_verify.o ssl_params.o ssl_error.o ssl_env.o

ucspissl.o: compile ucspissl.c ucspissl.h stralloc.h gen_alloc.h
	./compile ucspissl.c

uint16_pack.o: compile uint16_pack.c uint16.h
	./compile uint16_pack.c

uint16_unpack.o: compile uint16_unpack.c uint16.h
	./compile uint16_unpack.c

uint32.h: choose compile load tryulong32.c uint32.h1 uint32.h2
	./choose clr tryulong32 uint32.h1 uint32.h2 >uint32.h

uint32_pack.o: compile uint32_pack.c uint32.h
	./compile uint32_pack.c

uint32_unpack.o: compile uint32_unpack.c uint32.h
	./compile uint32_unpack.c

uint64.h: choose compile load tryulong64.c uint64.h1 uint64.h2
	./choose clr tryulong64 uint64.h1 uint64.h2 >uint64.h

unix.a: makelib alloc.o alloc_re.o buffer.o buffer_0.o buffer_1.o \
buffer_2.o buffer_get.o buffer_put.o buffer_copy.o buffer_read.o \
buffer_write.o env.o error.o error_str.o fd_copy.o fd_move.o fmt_ulong.o \
getln.o getln2.o socket_accept.o socket_bind.o socket_conn.o \
socket_delay.o socket_listen.o socket_local.o socket_opts.o \
socket_remote.o socket_tcp.o ndelay_on.o ndelay_off.o \
open_append.o open_read.o open_trunc.o openreadclose.o pathexec_env.o \
pathexec_run.o prot.o readclose.o seek_set.o sgetopt.o sig.o sig_block.o \
sig_catch.o sig_pause.o str_chr.o str_diff.o str_len.o str_start.o \
stralloc_cat.o stralloc_catb.o stralloc_cats.o stralloc_copy.o \
stralloc_eady.o stralloc_opyb.o stralloc_opys.o stralloc_pend.o \
strerr_die.o strerr_sys.o subgetopt.o wait_nohang.o wait_pid.o byte_chr.o \
byte_copy.o byte_cr.o byte_diff.o byte_zero.o case_diffb.o case_diffs.o \
ip_fmt.o scan_ulong.o scan_uint.o uint16_pack.o \
uint16_unpack.o uint32_pack.o uint32_unpack.o iopause.o tai_pack.o \
taia_add.o taia_approx.o taia_frac.o taia_less.o taia_now.o taia_pack.o \
taia_sub.o taia_uint.o dns_name.o lock_ex.o lock_un.o coe.o
	./makelib unix.a alloc.o alloc_re.o buffer.o buffer_0.o buffer_1.o \
	buffer_2.o buffer_get.o buffer_put.o buffer_copy.o buffer_read.o \
	buffer_write.o env.o error.o error_str.o fd_copy.o fd_move.o fmt_ulong.o \
	getln.o getln2.o socket_accept.o socket_bind.o socket_conn.o \
	socket_delay.o socket_listen.o socket_local.o socket_opts.o \
	socket_remote.o socket_tcp.o ndelay_on.o ndelay_off.o \
	open_append.o open_read.o open_trunc.o openreadclose.o pathexec_env.o \
	pathexec_run.o prot.o readclose.o seek_set.o sgetopt.o sig.o sig_block.o \
	sig_catch.o sig_pause.o str_chr.o str_diff.o str_len.o str_start.o \
	stralloc_cat.o stralloc_catb.o stralloc_cats.o stralloc_copy.o \
	stralloc_eady.o stralloc_opyb.o stralloc_opys.o stralloc_pend.o \
	strerr_die.o strerr_sys.o subgetopt.o wait_nohang.o wait_pid.o \
	byte_chr.o byte_copy.o byte_cr.o byte_diff.o byte_zero.o case_diffb.o \
	case_diffs.o ip_fmt.o scan_ulong.o scan_uint.o uint16_pack.o \
	uint16_unpack.o uint32_pack.o uint32_unpack.o iopause.o tai_pack.o \
	taia_add.o taia_approx.o taia_frac.o taia_less.o taia_now.o taia_pack.o \
	taia_sub.o taia_uint.o dns_name.o lock_ex.o lock_un.o coe.o

wait_nohang.o: compile wait_nohang.c haswaitp.h
	./compile wait_nohang.c

wait_pid.o: compile wait_pid.c error.h haswaitp.h
	./compile wait_pid.c
