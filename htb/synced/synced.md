# Synced

target IP: 10.129.213.222
rsync default port: 873

using `rsync rsync://TARGET_IP --list-only`
we find 3 directories
the flag is in the public directory
we get it with `rsync rsync://TARGET_IP/public/flag.txt .`

flag is: 72eaf5344ebb84908ae543a719830519
