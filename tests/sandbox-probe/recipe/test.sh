#!/bin/bash
# Exercises the §20.8 reference launcher end to end, as a non-root user.
# Each row runs the command confined (through the helper) and unconfined (control).
# Rows report PASS (confined as intended), LIMIT (reachable, as documented for
# this ABI: a known gap, not confinement), SKIP (cannot be shown here) or FAIL.
# Exit status: 0 all rows passed; 1 a row failed; 3 Landlock ABI below 3, so only
# the refusal rows ran (unsupported, not passed).
# Usage: test.sh <recipe-test binary>
set -u
BIN=$1
W=$(mktemp -d /tmp/rt-work.XXXX)      # the work directory
O=$(mktemp -d /tmp/rt-outside.XXXX)   # stands in for the agent's home and the rest of the filesystem
ABI=$(python3 -c 'import ctypes; r=ctypes.CDLL(None,use_errno=True).syscall(444,0,0,1); print(max(r,0))')
ALLOWED=18080; OTHER=18081
RO='"/usr","/bin","/sbin","/lib","/lib64","/etc","/proc"'
BASE="\"workDir\":\"$W\",\"readOnly\":[$RO],\"readWrite\":[\"/dev/null\"]"
PROXY="{$BASE,\"tcp\":\"proxy-port\",\"proxyPort\":$ALLOWED}"
DENY="{$BASE,\"tcp\":\"deny\"}"
FSONLY="{$BASE,\"tcp\":\"unrestricted\"}"
UNIXONLY="{$BASE,\"tcp\":\"unrestricted\",\"unixSocketsOnly\":true}"

reset() {
  find "$W" "$O" -mindepth 1 ! -name "*.sock" -delete
  echo keep > "$O/existing"; echo gone > "$O/removable"; mkdir "$O/emptydir"; : > "$O/leak"
  mkdir "$W/a" "$W/b"
}
reset
python3 -m http.server $ALLOWED --bind 127.0.0.1 >/dev/null 2>&1 & S1=$!
python3 -m http.server $ALLOWED --bind 127.0.0.2 >/dev/null 2>&1 & S2=$!
python3 -m http.server $OTHER --bind 127.0.0.1 >/dev/null 2>&1 & S3=$!
# A Unix-socket "proxy" in the work dir, an unintended Unix service outside it,
# and an abstract socket, all owned by the agent side.
python3 -c "
import socket,threading
def serve(addr):
    s=socket.socket(socket.AF_UNIX); s.bind(addr); s.listen(16)
    while True: s.accept()[0].close()
for a in ['$W/proxy.sock','$O/agent.sock','\0nic-agent-ctl']: threading.Thread(target=serve,args=(a,),daemon=True).start()
threading.Event().wait()" & S4=$!
sleep 300 & BYSTANDER=$!
sleep 1
cleanup() { kill $S1 $S2 $S3 $S4 $BYSTANDER 2>/dev/null; rm -rf "$W" "$O"; }

pass=0; fail=0; limit=0; skip=0
run() { # run <mode> <policy> <cmd>; prints allow or deny
  if [ "$1" = control ]; then "$BIN" control "$O/leak" /bin/sh -c "$3" >/dev/null 2>&1
  else "$BIN" agent "$2" "$O/leak" /bin/sh -c "$3" >/dev/null 2>&1; fi
  [ $? -eq 0 ] && echo allow || echo deny
}
# row <policy> <name> <expected confined result> <command> [limit]
# With "limit", an expected "allow" is a documented gap at this ABI (LIMIT), not a pass.
row() {
  local c u r; reset
  c=$(run agent "$1" "$4"); reset; u=$(run control "" "$4")
  if [ "$c" != "$3" ] || [ "$u" != allow ]; then r=FAIL; fail=$((fail+1))
  elif [ "${5:-}" = limit ] && [ "$c" = allow ]; then r=LIMIT; limit=$((limit+1))
  else r=PASS; pass=$((pass+1)); fi
  printf '%-5s %-62s confined=%-5s (want %-5s) control=%s\n' "$r" "$2" "$c" "$3" "$u"
}
# errrow <policy> <name> <expected confined output> <expected control output> <command>
# Compares what the command prints (an errno name), so a denial by the
# launcher's filter is told apart from the kernel's own answer.
errrow() {
  local c u r; reset
  c=$("$BIN" agent "$1" "$O/leak" /bin/sh -c "$5" 2>/dev/null); reset
  u=$("$BIN" control "$O/leak" /bin/sh -c "$5" 2>/dev/null)
  if [ "$u" != "$4" ] && [ "$u" = EPERM ]; then r=SKIP; skip=$((skip+1))   # already denied outside the sandbox
  elif [ "$c" = "$3" ] && [ "$u" = "$4" ]; then r=PASS; pass=$((pass+1))
  else r=FAIL; fail=$((fail+1)); fi
  printf '%-5s %-62s confined=%-6s (want %-6s) control=%s\n' "$r" "$2" "$c" "$3" "$u"
}
# refusal <policy> <name> <runs|refused>: the helper must refuse before executing anything.
refusal() {
  local got r; reset
  "$BIN" agent "$1" "$O/leak" /bin/sh -c ": > $W/ran" >/dev/null 2>&1; local status=$?
  if [ -e "$W/ran" ] && [ $status -eq 0 ]; then got=runs
  elif [ ! -e "$W/ran" ] && [ $status -eq 126 ]; then got=refused
  else got="status-$status"; fi
  if [ "$got" = "$3" ]; then r=PASS; pass=$((pass+1)); else r=FAIL; fail=$((fail+1)); fi
  printf '%-5s %-62s got=%-7s (want %s)\n' "$r" "$2" "$got" "$3"
}
py() { echo "python3 -c '$1'"; }
# Prints "ok" or the errno name of socket(<family>, <type>, 0).
sock() { py "import ctypes,errno; l=ctypes.CDLL(None,use_errno=True); r=l.socket($1,$2,0); print(\"ok\" if r>=0 else errno.errorcode[ctypes.get_errno()])"; }

echo "kernel: $(uname -r) arch: $(uname -m) user: uid=$(id -u) Landlock ABI: $ABI $(grep -E '^(Seccomp|NoNewPrivs|CapEff):' /proc/self/status | tr '\n\t' '  ')"
want() { [ "$ABI" -ge "$1" ] && echo runs || echo refused; }
SIG=deny; ABS=deny; [ "$ABI" -lt 6 ] && SIG=allow && ABS=allow
UNIX=deny; [ "$ABI" -lt 9 ] && UNIX=allow   # ABI 9: pathname Unix socket connect
UDP=deny; [ "$ABI" -lt 10 ] && UDP=allow    # ABI 10: UDP port rules

echo "--- policy refusal (fail closed) ---"
refusal "$PROXY"    "tcp proxy-port (needs ABI 4)"                            "$(want 4)"
refusal "$DENY"     "tcp deny (needs ABI 4)"                                  "$(want 4)"
refusal "$FSONLY"   "tcp unrestricted (needs ABI 3)"                          "$(want 3)"
refusal "$UNIXONLY" "tcp unrestricted, Unix sockets only (needs ABI 3)"       "$(want 3)"
refusal "{$BASE}"   "tcp mode not stated"                                     refused
refusal "{$BASE,\"tcp\":\"proxy-port\"}" "tcp proxy-port without a port"      refused
if [ "$ABI" -lt 3 ]; then
  cleanup
  echo "RESULT kernel=$(uname -r) abi=$ABI pass=$pass fail=$fail limit=$limit skip=$skip unsupported=1"
  [ $fail -eq 0 ] && exit 3 || exit 1
fi

MAIN=$PROXY; [ "$ABI" -lt 4 ] && MAIN=$FSONLY
echo "--- filesystem: writes ---"
row "$MAIN" "write, mkdir, symlink, rename inside work dir"     allow "echo x > $W/f && mkdir $W/d && ln -s f $W/l && mv $W/f $W/a/f && mv $W/a/f $W/b/f"
row "$MAIN" "create file outside"                               deny  "echo x > $O/new"
row "$MAIN" "append to file outside"                            deny  "echo x >> $O/existing"
row "$MAIN" "truncate file outside"                             deny  ": > $O/existing"
row "$MAIN" "remove file outside"                               deny  "rm $O/removable"
row "$MAIN" "mkdir outside"                                     deny  "mkdir $O/newdir"
row "$MAIN" "symlink outside (planting, e.g. ~/.gitconfig)"     deny  "ln -s $W/evil $O/.gitconfig"
row "$MAIN" "rmdir outside"                                     deny  "rmdir $O/emptydir"
row "$MAIN" "mkfifo outside"                                    deny  "mkfifo $O/fifo"
row "$MAIN" "make Unix socket outside"                          deny  "$(py "import socket; socket.socket(socket.AF_UNIX).bind(\"$O/s\")")"
row "$MAIN" "move file from work dir to outside"                deny  "echo x > $W/m && mv $W/m $O/m"
row "$MAIN" "grandchild writes outside (inherited)"             deny  "sh -c 'sh -c \"echo x > $O/gc\"'"
row "$MAIN" "write to /dev/null"                                allow "echo x > /dev/null"
row "$MAIN" "chmod file outside (metadata: not covered)"        allow "chmod 600 $O/existing" limit
echo "--- filesystem: reads ---"
row "$MAIN" "read and execute under granted paths"              allow "cat /etc/hostname >/dev/null && ls /usr/bin >/dev/null"
row "$MAIN" "read file outside granted paths (agent home)"      deny  "cat $O/existing"
row "$MAIN" "read file outside granted paths (/var)"            deny  "cat /var/lib/dpkg/status"
if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
row "$MAIN" "read mounted service-account token (stand-in)"     deny  "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
fi
row "$MAIN" "read agent's environment through /proc"            deny  "cat /proc/\$PPID/environ"
echo "--- environment and descriptors ---"
row "$MAIN" "agent secret in command's environment"             deny  "env | grep -q AGENT_SECRET"
row "$MAIN" "write through inherited descriptor 9"              deny  "$(py 'import os; os.write(9, b"x")')"
echo "--- IPC outside the sandbox ---"
row "$MAIN" "connect to Unix socket outside work dir (< ABI 9)" $UNIX "$(py "import socket; socket.socket(socket.AF_UNIX).connect(\"$O/agent.sock\")")" limit
row "$MAIN" "connect to abstract Unix socket (< ABI 6)"         $ABS  "$(py 'import socket; socket.socket(socket.AF_UNIX).connect("\0nic-agent-ctl")')" limit
row "$MAIN" "signal the parent agent process (< ABI 6)"         $SIG  "kill -0 \$PPID" limit  # sh is what the helper exec'd, so its parent is the agent
row "$MAIN" "signal another process of the same user (< ABI 6)" $SIG  "kill -0 $BYSTANDER" limit
if [ "$ABI" -ge 4 ]; then
echo "--- TCP: proxy-port ---"
row "$PROXY" "TCP connect to proxy port"                        allow "$(py "import socket; socket.create_connection((\"127.0.0.1\", $ALLOWED), 2)")"
row "$PROXY" "TCP connect to proxy port at another address"     allow "$(py "import socket; socket.create_connection((\"127.0.0.2\", $ALLOWED), 2)")"
row "$PROXY" "TCP connect to another port"                      deny  "$(py "import socket; socket.create_connection((\"127.0.0.1\", $OTHER), 2)")"
row "$PROXY" "TCP bind"                                         deny  "$(py 'import socket; socket.socket().bind(("127.0.0.1", 18090))')"
row "$PROXY" "UDP send (not covered below ABI 10)"              $UDP  "$(py 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))')" limit
echo "--- TCP: deny ---"
row "$DENY" "TCP connect to the port proxy-port would allow"    deny  "$(py "import socket; socket.create_connection((\"127.0.0.1\", $ALLOWED), 2)")"
row "$DENY" "TCP connect to another port"                       deny  "$(py "import socket; socket.create_connection((\"127.0.0.1\", $OTHER), 2)")"
row "$DENY" "TCP bind"                                          deny  "$(py 'import socket; socket.socket().bind(("127.0.0.1", 18090))')"
echo "--- TCP: unrestricted (filesystem only) ---"
row "$FSONLY" "TCP connect to any port"                         allow "$(py "import socket; socket.create_connection((\"127.0.0.1\", $OTHER), 2)")"
row "$FSONLY" "UDP send"                                        allow "$(py 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))')"
row "$FSONLY" "write outside work dir"                          deny  "echo x > $O/new"
fi
echo "--- Unix sockets only (seccomp; invalid socket type, so the kernel itself answers EINVAL) ---"
errrow "$UNIXONLY" "AF_INET denied by the filter"               EPERM  EINVAL "$(sock 2 256)"
errrow "$UNIXONLY" "AF_INET6 denied by the filter"              EPERM  EINVAL "$(sock 10 256)"
errrow "$UNIXONLY" "AF_NETLINK denied by the filter"            EPERM  EINVAL "$(sock 16 256)"
errrow "$UNIXONLY" "AF_PACKET denied by the filter"             EPERM  EINVAL "$(sock 17 256)"
errrow "$UNIXONLY" "AF_ALG denied by the filter"                EPERM  EINVAL "$(sock 38 256)"
errrow "$UNIXONLY" "AF_VSOCK denied by the filter"              EPERM  EINVAL "$(sock 40 256)"
errrow "$UNIXONLY" "AF_UNIX reaches the kernel"                 EINVAL EINVAL "$(sock 1 256)"
errrow "$UNIXONLY" "io_uring_setup denied by the filter"        EPERM  EFAULT "$(py 'import ctypes,errno; l=ctypes.CDLL(None,use_errno=True); r=l.syscall(425,1,None); print("ok" if r>=0 else errno.errorcode[ctypes.get_errno()])')"
echo "--- Unix sockets only (seccomp; real use) ---"
row "$UNIXONLY" "TCP connect to proxy port"                     deny  "$(py "import socket; socket.create_connection((\"127.0.0.1\", $ALLOWED), 2)")"
row "$UNIXONLY" "UDP send"                                      deny  "$(py 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))')"
row "$UNIXONLY" "IPv6 socket"                                   deny  "$(py 'import socket; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)')"
row "$UNIXONLY" "netlink socket"                                deny  "$(py 'import socket; socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)')"
row "$UNIXONLY" "Unix socket to proxy in work dir"              allow "$(py "import socket; socket.socket(socket.AF_UNIX).connect(\"$W/proxy.sock\")")"
row "$UNIXONLY" "unintended Unix service outside work dir (< ABI 9)" $UNIX "$(py "import socket; socket.socket(socket.AF_UNIX).connect(\"$O/agent.sock\")")" limit
row "$UNIXONLY" "abstract Unix socket (< ABI 6)"                $ABS  "$(py 'import socket; socket.socket(socket.AF_UNIX).connect("\0nic-agent-ctl")')" limit
row "$UNIXONLY" "ordinary command still runs (ls, sh)"          allow "ls $W >/dev/null && sh -c true"

cleanup
echo "RESULT kernel=$(uname -r) abi=$ABI pass=$pass fail=$fail limit=$limit skip=$skip"
[ $fail -eq 0 ]
