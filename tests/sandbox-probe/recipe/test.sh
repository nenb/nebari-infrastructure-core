#!/bin/bash
# Exercises the §20.8 reference launcher end to end, as a non-root user.
# Each row runs the command confined (through the helper) and unconfined (control).
# Usage: test.sh <recipe-test binary>
set -u
BIN=$1
W=$(mktemp -d /tmp/rt-work.XXXX)      # the work directory
O=$(mktemp -d /tmp/rt-outside.XXXX)   # stands in for the agent's home and the rest of the filesystem
ABI=$(python3 -c 'import ctypes,platform; n={"x86_64":444,"aarch64":444}[platform.machine()]; print(ctypes.CDLL(None,use_errno=True).syscall(n,0,0,1))')
ALLOWED=18080; OTHER=18081
RO='"/usr","/bin","/sbin","/lib","/lib64","/etc","/proc"'
POLICY="{\"WorkDir\":\"$W\",\"ReadOnly\":[$RO],\"ReadWrite\":[\"/dev/null\"],\"ProxyPort\":$ALLOWED}"
STRICT="{\"WorkDir\":\"$W\",\"ReadOnly\":[$RO],\"ReadWrite\":[\"/dev/null\"],\"NoInet\":true}"

reset() {
  find "$W" "$O" -mindepth 1 ! -name "*.sock" -delete
  echo keep > "$O/existing"; echo gone > "$O/removable"; mkdir "$O/emptydir"; : > "$O/leak"
  mkdir "$W/a" "$W/b"
}
reset
python3 -m http.server $ALLOWED --bind 127.0.0.1 >/dev/null 2>&1 & S1=$!
python3 -m http.server $ALLOWED --bind 127.0.0.2 >/dev/null 2>&1 & S2=$!
python3 -m http.server $OTHER --bind 127.0.0.1 >/dev/null 2>&1 & S3=$!
# A Unix-socket "proxy" in the work dir, one outside it, and an abstract socket, all owned by the agent side.
python3 -c "
import socket,threading
def serve(addr):
    s=socket.socket(socket.AF_UNIX); s.bind(addr); s.listen(16)
    while True: s.accept()[0].close()
for a in ['$W/proxy.sock','$O/agent.sock','\0nic-agent-ctl']: threading.Thread(target=serve,args=(a,),daemon=True).start()
threading.Event().wait()" & S4=$!
sleep 300 & BYSTANDER=$!
sleep 1

pass=0; fail=0
run() { # run <mode> <policy> <cmd>; prints allow or deny
  if [ "$1" = control ]; then "$BIN" control "$O/leak" /bin/sh -c "$3" >/dev/null 2>&1
  else "$BIN" agent "$2" "$O/leak" /bin/sh -c "$3" >/dev/null 2>&1; fi
  [ $? -eq 0 ] && echo allow || echo deny
}
# row <policy> <name> <expected confined result> <command>
row() {
  local c u r; reset
  c=$(run agent "$1" "$4"); reset; u=$(run control "" "$4")
  if [ "$c" = "$3" ] && [ "$u" = allow ]; then r=PASS; pass=$((pass+1)); else r=FAIL; fail=$((fail+1)); fi
  printf '%-4s %-58s confined=%-5s (want %-5s) control=%s\n' "$r" "$2" "$c" "$3" "$u"
}
py() { echo "python3 -c '$1'"; }

echo "kernel: $(uname -r) arch: $(uname -m) user: uid=$(id -u) Landlock ABI: $ABI $(grep -E '^(Seccomp|NoNewPrivs|CapEff):' /proc/self/status | tr '\n\t' '  ')"
SIG=deny; ABS=deny; [ "$ABI" -lt 6 ] && SIG=allow && ABS=allow
UNIX=deny; [ "$ABI" -lt 9 ] && UNIX=allow   # ABI 9: pathname Unix socket connect
UDP=deny; [ "$ABI" -lt 10 ] && UDP=allow    # ABI 10: UDP port rules

echo "--- filesystem: writes ---"
row "$POLICY" "write, mkdir, symlink, rename inside work dir"     allow "echo x > $W/f && mkdir $W/d && ln -s f $W/l && mv $W/f $W/a/f && mv $W/a/f $W/b/f"
row "$POLICY" "create file outside"                               deny  "echo x > $O/new"
row "$POLICY" "append to file outside"                            deny  "echo x >> $O/existing"
row "$POLICY" "truncate file outside"                             deny  ": > $O/existing"
row "$POLICY" "remove file outside"                               deny  "rm $O/removable"
row "$POLICY" "mkdir outside"                                     deny  "mkdir $O/newdir"
row "$POLICY" "symlink outside (planting, e.g. ~/.gitconfig)"     deny  "ln -s $W/evil $O/.gitconfig"
row "$POLICY" "rmdir outside"                                     deny  "rmdir $O/emptydir"
row "$POLICY" "mkfifo outside"                                    deny  "mkfifo $O/fifo"
row "$POLICY" "make Unix socket outside"                          deny  "$(py "import socket; socket.socket(socket.AF_UNIX).bind(\"$O/s\")")"
row "$POLICY" "move file from work dir to outside"                deny  "echo x > $W/m && mv $W/m $O/m"
row "$POLICY" "grandchild writes outside (inherited)"             deny  "sh -c 'sh -c \"echo x > $O/gc\"'"
row "$POLICY" "write to /dev/null"                                allow "echo x > /dev/null"
row "$POLICY" "chmod file outside (metadata: not covered)"        allow "chmod 600 $O/existing"
echo "--- filesystem: reads ---"
row "$POLICY" "read and execute under granted paths"              allow "cat /etc/hostname >/dev/null && ls /usr/bin >/dev/null"
row "$POLICY" "read file outside granted paths (agent home)"      deny  "cat $O/existing"
row "$POLICY" "read file outside granted paths (/var)"            deny  "cat /var/lib/dpkg/status"
if [ -e /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
row "$POLICY" "read mounted service-account token (stand-in)"     deny  "cat /var/run/secrets/kubernetes.io/serviceaccount/token"
fi
row "$POLICY" "read agent's environment through /proc"            deny  "cat /proc/\$PPID/environ"
echo "--- environment and descriptors ---"
row "$POLICY" "agent secret in command's environment"             deny  "env | grep -q AGENT_SECRET"
row "$POLICY" "write through inherited descriptor 9"              deny  "$(py 'import os; os.write(9, b"x")')"
echo "--- network (port rules) ---"
row "$POLICY" "TCP connect to proxy port"                         allow "$(py "import socket; socket.create_connection((\"127.0.0.1\", $ALLOWED), 2)")"
row "$POLICY" "TCP connect to proxy port at another address"      allow "$(py "import socket; socket.create_connection((\"127.0.0.2\", $ALLOWED), 2)")"
row "$POLICY" "TCP connect to another port"                       deny  "$(py "import socket; socket.create_connection((\"127.0.0.1\", $OTHER), 2)")"
row "$POLICY" "TCP bind"                                          deny  "$(py 'import socket; socket.socket().bind(("127.0.0.1", 18090))')"
row "$POLICY" "UDP send (not covered below ABI 10)"               $UDP  "$(py 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))')"
row "$POLICY" "connect to Unix socket outside work dir (< ABI 9)"  $UNIX "$(py "import socket; socket.socket(socket.AF_UNIX).connect(\"$O/agent.sock\")")"
row "$POLICY" "connect to abstract Unix socket outside sandbox"   $ABS  "$(py 'import socket; socket.socket(socket.AF_UNIX).connect("\0nic-agent-ctl")')"
row "$POLICY" "signal the parent agent process"                   $SIG  "kill -0 \$PPID"  # sh is what the helper exec'd, so its parent is the agent
row "$POLICY" "signal another process of the same user"           $SIG  "kill -0 $BYSTANDER"
echo "--- network (strict: seccomp denies IP, packet and netlink sockets) ---"
row "$STRICT" "TCP connect to proxy port"                         deny  "$(py "import socket; socket.create_connection((\"127.0.0.1\", $ALLOWED), 2)")"
row "$STRICT" "UDP send"                                          deny  "$(py 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.1", 9))')"
row "$STRICT" "IPv6 socket"                                       deny  "$(py 'import socket; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)')"
row "$STRICT" "netlink socket"                                    deny  "$(py 'import socket; socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)')"
row "$STRICT" "Unix socket to proxy in work dir"                  allow "$(py "import socket; socket.socket(socket.AF_UNIX).connect(\"$W/proxy.sock\")")"
row "$STRICT" "ordinary command still runs (ls, sh)"              allow "ls $W >/dev/null && sh -c true"

kill $S1 $S2 $S3 $S4 $BYSTANDER 2>/dev/null
rm -rf "$W" "$O"
echo "RESULT kernel=$(uname -r) abi=$ABI pass=$pass fail=$fail"
[ $fail -eq 0 ]
