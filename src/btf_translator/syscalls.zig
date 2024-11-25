pub const read = fn (
    fd: Kernel.unsigned_int,
    buf: *Kernel.char,
    count: Kernel.size_t,
) c_long;
pub const write = fn (
    fd: Kernel.unsigned_int,
    buf: *Kernel.char,
    count: Kernel.size_t,
) c_long;
pub const open = fn (
    filename: *Kernel.char,
    flags: Kernel.int,
    mode: Kernel.umode_t,
) c_long;
pub const close = fn (
    fd: Kernel.unsigned_int,
) c_long;
pub const newstat = fn (
    filename: *Kernel.char,
    statbuf: *Kernel.stat,
) c_long;
pub const newfstat = fn (
    fd: Kernel.unsigned_int,
    statbuf: *Kernel.stat,
) c_long;
pub const newlstat = fn (
    filename: *Kernel.char,
    statbuf: *Kernel.stat,
) c_long;
pub const poll = fn (
    ufds: *Kernel.pollfd,
    nfds: Kernel.unsigned_int,
    timeout_msecs: Kernel.int,
) c_long;
pub const lseek = fn (
    fd: Kernel.unsigned_int,
    offset: Kernel.off_t,
    whence: Kernel.unsigned_int,
) c_long;
pub const mmap = fn (
    addr: c_ulong,
    len: c_ulong,
    prot: c_ulong,
    flags: c_ulong,
    fd: c_ulong,
    off: c_ulong,
) c_long;
pub const mprotect = fn (
    start: c_ulong,
    len: Kernel.size_t,
    prot: c_ulong,
) c_long;
pub const munmap = fn (
    addr: c_ulong,
    len: Kernel.size_t,
) c_long;
pub const brk = fn (
    brk: c_ulong,
) c_long;
pub const rt_sigaction = fn (
    sig: Kernel.int,
    act: *Kernel.sigaction,
    oact: *Kernel.sigaction,
    sigsetsize: Kernel.size_t,
) c_long;
pub const rt_sigprocmask = fn (
    how: Kernel.int,
    nset: *Kernel.sigset_t,
    oset: *Kernel.sigset_t,
    sigsetsize: Kernel.size_t,
) c_long;
pub const rt_sigreturn = fn () c_long;
pub const ioctl = fn (
    fd: Kernel.unsigned_int,
    cmd: Kernel.unsigned_int,
    arg: c_ulong,
) c_long;
pub const pread64 = fn (
    fd: Kernel.unsigned_int,
    buf: *Kernel.char,
    count: Kernel.size_t,
    pos: Kernel.loff_t,
) c_long;
pub const pwrite64 = fn (
    fd: Kernel.unsigned_int,
    buf: *Kernel.char,
    count: Kernel.size_t,
    pos: Kernel.loff_t,
) c_long;
pub const readv = fn (
    fd: c_ulong,
    vec: *Kernel.iovec,
    vlen: c_ulong,
) c_long;
pub const writev = fn (
    fd: c_ulong,
    vec: *Kernel.iovec,
    vlen: c_ulong,
) c_long;
pub const access = fn (
    filename: *Kernel.char,
    mode: Kernel.int,
) c_long;
pub const pipe = fn (
    fildes: *Kernel.int,
) c_long;
pub const select = fn (
    n: Kernel.int,
    inp: *Kernel.fd_set,
    outp: *Kernel.fd_set,
    exp: *Kernel.fd_set,
    tvp: *Kernel.__kernel_old_timeval,
) c_long;
pub const sched_yield = fn () c_long;
pub const mremap = fn (
    addr: c_ulong,
    old_len: c_ulong,
    new_len: c_ulong,
    flags: c_ulong,
    new_addr: c_ulong,
) c_long;
pub const msync = fn (
    start: c_ulong,
    len: Kernel.size_t,
    flags: Kernel.int,
) c_long;
pub const mincore = fn (
    start: c_ulong,
    len: Kernel.size_t,
    vec: *Kernel.unsigned_char,
) c_long;
pub const madvise = fn (
    start: c_ulong,
    len_in: Kernel.size_t,
    behavior: Kernel.int,
) c_long;
pub const shmget = fn (
    key: Kernel.key_t,
    size: Kernel.size_t,
    shmflg: Kernel.int,
) c_long;
pub const shmat = fn (
    shmid: Kernel.int,
    shmaddr: *Kernel.char,
    shmflg: Kernel.int,
) c_long;
pub const shmctl = fn (
    shmid: Kernel.int,
    cmd: Kernel.int,
    buf: *Kernel.shmid_ds,
) c_long;
pub const dup = fn (
    fildes: Kernel.unsigned_int,
) c_long;
pub const dup2 = fn (
    oldfd: Kernel.unsigned_int,
    newfd: Kernel.unsigned_int,
) c_long;
pub const pause = fn () c_long;
pub const nanosleep = fn (
    rqtp: *Kernel.__kernel_timespec,
    rmtp: *Kernel.__kernel_timespec,
) c_long;
pub const getitimer = fn (
    which: Kernel.int,
    value: *Kernel.__kernel_old_itimerval,
) c_long;
pub const alarm = fn (
    seconds: Kernel.unsigned_int,
) c_long;
pub const setitimer = fn (
    which: Kernel.int,
    value: *Kernel.__kernel_old_itimerval,
    ovalue: *Kernel.__kernel_old_itimerval,
) c_long;
pub const getpid = fn () c_long;
pub const sendfile64 = fn (
    out_fd: Kernel.int,
    in_fd: Kernel.int,
    offset: *Kernel.loff_t,
    count: Kernel.size_t,
) c_long;
pub const socket = fn (
    family: Kernel.int,
    type: Kernel.int,
    protocol: Kernel.int,
) c_long;
pub const connect = fn (
    fd: Kernel.int,
    uservaddr: *Kernel.sockaddr,
    addrlen: Kernel.int,
) c_long;
pub const accept = fn (
    fd: Kernel.int,
    upeer_sockaddr: *Kernel.sockaddr,
    upeer_addrlen: *Kernel.int,
) c_long;
pub const sendto = fn (
    fd: Kernel.int,
    buff: *Kernel.void,
    len: Kernel.size_t,
    flags: Kernel.unsigned_int,
    addr: *Kernel.sockaddr,
    addr_len: Kernel.int,
) c_long;
pub const recvfrom = fn (
    fd: Kernel.int,
    ubuf: *Kernel.void,
    size: Kernel.size_t,
    flags: Kernel.unsigned_int,
    addr: *Kernel.sockaddr,
    addr_len: *Kernel.int,
) c_long;
pub const sendmsg = fn (
    fd: Kernel.int,
    msg: *Kernel.user_msghdr,
    flags: Kernel.unsigned_int,
) c_long;
pub const recvmsg = fn (
    fd: Kernel.int,
    msg: *Kernel.user_msghdr,
    flags: Kernel.unsigned_int,
) c_long;
pub const shutdown = fn (
    fd: Kernel.int,
    how: Kernel.int,
) c_long;
pub const bind = fn (
    fd: Kernel.int,
    umyaddr: *Kernel.sockaddr,
    addrlen: Kernel.int,
) c_long;
pub const listen = fn (
    fd: Kernel.int,
    backlog: Kernel.int,
) c_long;
pub const getsockname = fn (
    fd: Kernel.int,
    usockaddr: *Kernel.sockaddr,
    usockaddr_len: *Kernel.int,
) c_long;
pub const getpeername = fn (
    fd: Kernel.int,
    usockaddr: *Kernel.sockaddr,
    usockaddr_len: *Kernel.int,
) c_long;
pub const socketpair = fn (
    family: Kernel.int,
    type: Kernel.int,
    protocol: Kernel.int,
    usockvec: *Kernel.int,
) c_long;
pub const setsockopt = fn (
    fd: Kernel.int,
    level: Kernel.int,
    optname: Kernel.int,
    optval: *Kernel.char,
    optlen: Kernel.int,
) c_long;
pub const getsockopt = fn (
    fd: Kernel.int,
    level: Kernel.int,
    optname: Kernel.int,
    optval: *Kernel.char,
    optlen: *Kernel.int,
) c_long;
pub const clone = fn (
    clone_flags: c_ulong,
    newsp: c_ulong,
    parent_tidptr: *Kernel.int,
    child_tidptr: *Kernel.int,
    tls: c_ulong,
) c_long;
pub const fork = fn () c_long;
pub const vfork = fn () c_long;
pub const execve = fn (
    filename: *Kernel.char,
    argv: **Kernel.char,
    envp: **Kernel.char,
) c_long;
pub const exit = fn (
    error_code: Kernel.int,
) c_long;
pub const wait4 = fn (
    upid: Kernel.pid_t,
    stat_addr: *Kernel.int,
    options: Kernel.int,
    ru: *Kernel.rusage,
) c_long;
pub const kill = fn (
    pid: Kernel.pid_t,
    sig: Kernel.int,
) c_long;
pub const newuname = fn (
    name: *Kernel.new_utsname,
) c_long;
pub const semget = fn (
    key: Kernel.key_t,
    nsems: Kernel.int,
    semflg: Kernel.int,
) c_long;
pub const semop = fn (
    semid: Kernel.int,
    tsops: *Kernel.sembuf,
    nsops: unsigned_int,
) c_long;
pub const semctl = fn (
    semid: Kernel.int,
    semnum: Kernel.int,
    cmd: Kernel.int,
    arg: c_ulong,
) c_long;
pub const shmdt = fn (
    shmaddr: *Kernel.char,
) c_long;
pub const msgget = fn (
    key: Kernel.key_t,
    msgflg: Kernel.int,
) c_long;
pub const msgsnd = fn (
    msqid: Kernel.int,
    msgp: *Kernel.msgbuf,
    msgsz: Kernel.size_t,
    msgflg: Kernel.int,
) c_long;
pub const msgrcv = fn (
    msqid: Kernel.int,
    msgp: *Kernel.msgbuf,
    msgsz: Kernel.size_t,
    msgtyp: long_int,
    msgflg: Kernel.int,
) c_long;
pub const msgctl = fn (
    msqid: Kernel.int,
    cmd: Kernel.int,
    buf: *Kernel.msqid_ds,
) c_long;
pub const fcntl = fn (
    fd: Kernel.unsigned_int,
    cmd: Kernel.unsigned_int,
    arg: c_ulong,
) c_long;
pub const flock = fn (
    fd: Kernel.unsigned_int,
    cmd: Kernel.unsigned_int,
) c_long;
pub const fsync = fn (
    fd: Kernel.unsigned_int,
) c_long;
pub const fdatasync = fn (
    fd: Kernel.unsigned_int,
) c_long;
pub const truncate = fn (
    path: *Kernel.char,
    length: long_int,
) c_long;
pub const ftruncate = fn (
    fd: Kernel.unsigned_int,
    length: Kernel.off_t,
) c_long;
pub const getdents = fn (
    fd: Kernel.unsigned_int,
    dirent: *Kernel.linux_dirent,
    count: Kernel.unsigned_int,
) c_long;
pub const getcwd = fn (
    buf: *Kernel.char,
    size: c_ulong,
) c_long;
pub const chdir = fn (
    filename: *Kernel.char,
) c_long;
pub const fchdir = fn (
    fd: Kernel.unsigned_int,
) c_long;
pub const rename = fn (
    oldname: *Kernel.char,
    newname: *Kernel.char,
) c_long;
pub const mkdir = fn (
    pathname: *Kernel.char,
    mode: Kernel.umode_t,
) c_long;
pub const rmdir = fn (
    pathname: *Kernel.char,
) c_long;
pub const creat = fn (
    pathname: *Kernel.char,
    mode: Kernel.umode_t,
) c_long;
pub const link = fn (
    oldname: *Kernel.char,
    newname: *Kernel.char,
) c_long;
pub const unlink = fn (
    pathname: *Kernel.char,
) c_long;
pub const symlink = fn (
    oldname: *Kernel.char,
    newname: *Kernel.char,
) c_long;
pub const readlink = fn (
    path: *Kernel.char,
    buf: *Kernel.char,
    bufsiz: Kernel.int,
) c_long;
pub const chmod = fn (
    filename: *Kernel.char,
    mode: Kernel.umode_t,
) c_long;
pub const fchmod = fn (
    fd: Kernel.unsigned_int,
    mode: Kernel.umode_t,
) c_long;
pub const chown = fn (
    filename: *Kernel.char,
    user: Kernel.uid_t,
    group: Kernel.gid_t,
) c_long;
pub const fchown = fn (
    fd: Kernel.unsigned_int,
    user: Kernel.uid_t,
    group: Kernel.gid_t,
) c_long;
pub const lchown = fn (
    filename: *Kernel.char,
    user: Kernel.uid_t,
    group: Kernel.gid_t,
) c_long;
pub const umask = fn (
    mask: Kernel.int,
) c_long;
pub const gettimeofday = fn (
    tv: *Kernel.__kernel_old_timeval,
    tz: *Kernel.timezone,
) c_long;
pub const getrlimit = fn (
    resource: Kernel.unsigned_int,
    rlim: *Kernel.rlimit,
) c_long;
pub const getrusage = fn (
    who: Kernel.int,
    ru: *Kernel.rusage,
) c_long;
pub const sysinfo = fn (
    info: *Kernel.sysinfo,
) c_long;
pub const times = fn (
    tbuf: *Kernel.tms,
) c_long;
pub const ptrace = fn (
    request: long_int,
    pid: long_int,
    addr: c_ulong,
    data: c_ulong,
) c_long;
pub const getuid = fn () c_long;
pub const syslog = fn (
    type: Kernel.int,
    buf: *Kernel.char,
    len: Kernel.int,
) c_long;
pub const getgid = fn () c_long;
pub const setuid = fn (
    uid: Kernel.uid_t,
) c_long;
pub const setgid = fn (
    gid: Kernel.gid_t,
) c_long;
pub const geteuid = fn () c_long;
pub const getegid = fn () c_long;
pub const setpgid = fn (
    pid: Kernel.pid_t,
    pgid: Kernel.pid_t,
) c_long;
pub const getppid = fn () c_long;
pub const getpgrp = fn () c_long;
pub const setsid = fn () c_long;
pub const setreuid = fn (
    ruid: Kernel.uid_t,
    euid: Kernel.uid_t,
) c_long;
pub const setregid = fn (
    rgid: Kernel.gid_t,
    egid: Kernel.gid_t,
) c_long;
pub const getgroups = fn (
    gidsetsize: Kernel.int,
    grouplist: *Kernel.gid_t,
) c_long;
pub const setgroups = fn (
    gidsetsize: Kernel.int,
    grouplist: *Kernel.gid_t,
) c_long;
pub const setresuid = fn (
    ruid: Kernel.uid_t,
    euid: Kernel.uid_t,
    suid: Kernel.uid_t,
) c_long;
pub const getresuid = fn (
    ruidp: *Kernel.uid_t,
    euidp: *Kernel.uid_t,
    suidp: *Kernel.uid_t,
) c_long;
pub const setresgid = fn (
    rgid: Kernel.gid_t,
    egid: Kernel.gid_t,
    sgid: Kernel.gid_t,
) c_long;
pub const getresgid = fn (
    rgidp: *Kernel.gid_t,
    egidp: *Kernel.gid_t,
    sgidp: *Kernel.gid_t,
) c_long;
pub const getpgid = fn (
    pid: Kernel.pid_t,
) c_long;
pub const setfsuid = fn (
    uid: Kernel.uid_t,
) c_long;
pub const setfsgid = fn (
    gid: Kernel.gid_t,
) c_long;
pub const getsid = fn (
    pid: Kernel.pid_t,
) c_long;
pub const capget = fn (
    header: Kernel.cap_user_header_t,
    dataptr: Kernel.cap_user_data_t,
) c_long;
pub const capset = fn (
    header: Kernel.cap_user_header_t,
    data: Kernel.cap_user_data_t,
) c_long;
pub const rt_sigpending = fn (
    uset: *Kernel.sigset_t,
    sigsetsize: Kernel.size_t,
) c_long;
pub const rt_sigtimedwait = fn (
    uthese: *Kernel.sigset_t,
    uinfo: *Kernel.siginfo_t,
    uts: *Kernel.__kernel_timespec,
    sigsetsize: Kernel.size_t,
) c_long;
pub const rt_sigqueueinfo = fn (
    pid: Kernel.pid_t,
    sig: Kernel.int,
    uinfo: *Kernel.siginfo_t,
) c_long;
pub const rt_sigsuspend = fn (
    unewset: *Kernel.sigset_t,
    sigsetsize: Kernel.size_t,
) c_long;
pub const sigaltstack = fn (
    uss: *Kernel.stack_t,
    uoss: *Kernel.stack_t,
) c_long;
pub usingnamespace if (@hasDecl(Kernel, "utimbuf")) struct {
    pub const utime = fn (
        filename: *Kernel.char,
        times: *Kernel.utimbuf,
    ) c_long;
} else struct {};
pub const mknod = fn (
    filename: *Kernel.char,
    mode: Kernel.umode_t,
    dev: unsigned_int,
) c_long;
pub const personality = fn (
    personality: Kernel.unsigned_int,
) c_long;
pub const ustat = fn (
    dev: unsigned_int,
    ubuf: *Kernel.ustat,
) c_long;
pub const statfs = fn (
    pathname: *Kernel.char,
    buf: *Kernel.statfs,
) c_long;
pub const fstatfs = fn (
    fd: Kernel.unsigned_int,
    buf: *Kernel.statfs,
) c_long;
pub const sysfs = fn (
    option: Kernel.int,
    arg1: c_ulong,
    arg2: c_ulong,
) c_long;
pub const getpriority = fn (
    which: Kernel.int,
    who: Kernel.int,
) c_long;
pub const setpriority = fn (
    which: Kernel.int,
    who: Kernel.int,
    niceval: Kernel.int,
) c_long;
pub const sched_setparam = fn (
    pid: Kernel.pid_t,
    param: *Kernel.sched_param,
) c_long;
pub const sched_getparam = fn (
    pid: Kernel.pid_t,
    param: *Kernel.sched_param,
) c_long;
pub const sched_setscheduler = fn (
    pid: Kernel.pid_t,
    policy: Kernel.int,
    param: *Kernel.sched_param,
) c_long;
pub const sched_getscheduler = fn (
    pid: Kernel.pid_t,
) c_long;
pub const sched_get_priority_max = fn (
    policy: Kernel.int,
) c_long;
pub const sched_get_priority_min = fn (
    policy: Kernel.int,
) c_long;
pub const sched_rr_get_interval = fn (
    pid: Kernel.pid_t,
    interval: *Kernel.__kernel_timespec,
) c_long;
pub const mlock = fn (
    start: c_ulong,
    len: Kernel.size_t,
) c_long;
pub const munlock = fn (
    start: c_ulong,
    len: Kernel.size_t,
) c_long;
pub const mlockall = fn (
    flags: Kernel.int,
) c_long;
pub const munlockall = fn () c_long;
pub const vhangup = fn () c_long;
pub const modify_ldt = fn (
    func: Kernel.int,
    ptr: *Kernel.void,
    bytecount: c_ulong,
) c_long;
pub const pivot_root = fn (
    new_root: *Kernel.char,
    put_old: *Kernel.char,
) c_long;
pub const prctl = fn (
    option: Kernel.int,
    arg2: c_ulong,
    arg3: c_ulong,
    arg4: c_ulong,
    arg5: c_ulong,
) c_long;
pub const arch_prctl = fn (
    option: Kernel.int,
    arg2: c_ulong,
) c_long;
pub const adjtimex = fn (
    txc_p: *Kernel.__kernel_timex,
) c_long;
pub const setrlimit = fn (
    resource: Kernel.unsigned_int,
    rlim: *Kernel.rlimit,
) c_long;
pub const chroot = fn (
    filename: *Kernel.char,
) c_long;
pub const sync = fn () c_long;
pub const acct = fn (
    name: *Kernel.char,
) c_long;
pub const settimeofday = fn (
    tv: *Kernel.__kernel_old_timeval,
    tz: *Kernel.timezone,
) c_long;
pub const mount = fn (
    dev_name: *Kernel.char,
    dir_name: *Kernel.char,
    type: *Kernel.char,
    flags: c_ulong,
    data: *Kernel.void,
) c_long;
pub const umount = fn (
    name: *Kernel.char,
    flags: Kernel.int,
) c_long;
pub const swapon = fn (
    specialfile: *Kernel.char,
    swap_flags: Kernel.int,
) c_long;
pub const swapoff = fn (
    specialfile: *Kernel.char,
) c_long;
pub const reboot = fn (
    magic1: Kernel.int,
    magic2: Kernel.int,
    cmd: Kernel.unsigned_int,
    arg: *Kernel.void,
) c_long;
pub const sethostname = fn (
    name: *Kernel.char,
    len: Kernel.int,
) c_long;
pub const setdomainname = fn (
    name: *Kernel.char,
    len: Kernel.int,
) c_long;
pub const iopl = fn (
    level: Kernel.unsigned_int,
) c_long;
pub const ioperm = fn (
    from: c_ulong,
    num: c_ulong,
    turn_on: Kernel.int,
) c_long;
pub const init_module = fn (
    umod: *Kernel.void,
    len: c_ulong,
    uargs: *Kernel.char,
) c_long;
pub const delete_module = fn (
    name_user: *Kernel.char,
    flags: Kernel.unsigned_int,
) c_long;
pub const quotactl = fn (
    cmd: Kernel.unsigned_int,
    special: *Kernel.char,
    id: Kernel.qid_t,
    addr: *Kernel.void,
) c_long;
pub const gettid = fn () c_long;
pub const readahead = fn (
    fd: Kernel.int,
    offset: Kernel.loff_t,
    count: Kernel.size_t,
) c_long;
pub const setxattr = fn (
    pathname: *Kernel.char,
    name: *Kernel.char,
    value: *Kernel.void,
    size: Kernel.size_t,
    flags: Kernel.int,
) c_long;
pub const lsetxattr = fn (
    pathname: *Kernel.char,
    name: *Kernel.char,
    value: *Kernel.void,
    size: Kernel.size_t,
    flags: Kernel.int,
) c_long;
pub const fsetxattr = fn (
    fd: Kernel.int,
    name: *Kernel.char,
    value: *Kernel.void,
    size: Kernel.size_t,
    flags: Kernel.int,
) c_long;
pub const getxattr = fn (
    pathname: *Kernel.char,
    name: *Kernel.char,
    value: *Kernel.void,
    size: Kernel.size_t,
) c_long;
pub const lgetxattr = fn (
    pathname: *Kernel.char,
    name: *Kernel.char,
    value: *Kernel.void,
    size: Kernel.size_t,
) c_long;
pub const fgetxattr = fn (
    fd: Kernel.int,
    name: *Kernel.char,
    value: *Kernel.void,
    size: Kernel.size_t,
) c_long;
pub const listxattr = fn (
    pathname: *Kernel.char,
    list: *Kernel.char,
    size: Kernel.size_t,
) c_long;
pub const llistxattr = fn (
    pathname: *Kernel.char,
    list: *Kernel.char,
    size: Kernel.size_t,
) c_long;
pub const flistxattr = fn (
    fd: Kernel.int,
    list: *Kernel.char,
    size: Kernel.size_t,
) c_long;
pub const removexattr = fn (
    pathname: *Kernel.char,
    name: *Kernel.char,
) c_long;
pub const lremovexattr = fn (
    pathname: *Kernel.char,
    name: *Kernel.char,
) c_long;
pub const fremovexattr = fn (
    fd: Kernel.int,
    name: *Kernel.char,
) c_long;
pub const tkill = fn (
    pid: Kernel.pid_t,
    sig: Kernel.int,
) c_long;
pub const time = fn (
    tloc: *Kernel.__kernel_old_time_t,
) c_long;
pub const futex = fn (
    uaddr: *Kernel.u32,
    op: Kernel.int,
    val: Kernel.u32,
    utime: *Kernel.__kernel_timespec,
    uaddr2: *Kernel.u32,
    val3: Kernel.u32,
) c_long;
pub const sched_setaffinity = fn (
    pid: Kernel.pid_t,
    len: Kernel.unsigned_int,
    user_mask_ptr: *c_ulong,
) c_long;
pub const sched_getaffinity = fn (
    pid: Kernel.pid_t,
    len: Kernel.unsigned_int,
    user_mask_ptr: *c_ulong,
) c_long;
pub const io_setup = fn (
    nr_events: unsigned_int,
    ctxp: *Kernel.aio_context_t,
) c_long;
pub const io_destroy = fn (
    ctx: Kernel.aio_context_t,
) c_long;
pub const io_getevents = fn (
    ctx_id: Kernel.aio_context_t,
    min_nr: long_int,
    nr: long_int,
    events: *Kernel.io_event,
    timeout: *Kernel.__kernel_timespec,
) c_long;
pub const io_submit = fn (
    ctx_id: Kernel.aio_context_t,
    nr: long_int,
    iocbpp: **Kernel.iocb,
) c_long;
pub const io_cancel = fn (
    ctx_id: Kernel.aio_context_t,
    iocb: *Kernel.iocb,
    result: *Kernel.io_event,
) c_long;
pub const epoll_create = fn (
    size: Kernel.int,
) c_long;
pub const remap_file_pages = fn (
    start: c_ulong,
    size: c_ulong,
    prot: c_ulong,
    pgoff: c_ulong,
    flags: c_ulong,
) c_long;
pub const getdents64 = fn (
    fd: Kernel.unsigned_int,
    dirent: *Kernel.linux_dirent64,
    count: Kernel.unsigned_int,
) c_long;
pub const set_tid_address = fn (
    tidptr: *Kernel.int,
) c_long;
pub const restart_syscall = fn () c_long;
pub const semtimedop = fn (
    semid: Kernel.int,
    tsops: *Kernel.sembuf,
    nsops: Kernel.unsigned_int,
    timeout: *Kernel.__kernel_timespec,
) c_long;
pub const fadvise64 = fn (
    fd: Kernel.int,
    offset: Kernel.loff_t,
    len: Kernel.loff_t,
    advice: Kernel.int,
) c_long;
pub const timer_create = fn (
    which_clock: Kernel.clockid_t,
    timer_event_spec: *Kernel.sigevent,
    created_timer_id: *Kernel.timer_t,
) c_long;
pub const timer_settime = fn (
    timer_id: Kernel.timer_t,
    flags: Kernel.int,
    new_setting: *Kernel.__kernel_itimerspec,
    old_setting: *Kernel.__kernel_itimerspec,
) c_long;
pub const timer_gettime = fn (
    timer_id: Kernel.timer_t,
    setting: *Kernel.__kernel_itimerspec,
) c_long;
pub const timer_getoverrun = fn (
    timer_id: Kernel.timer_t,
) c_long;
pub const timer_delete = fn (
    timer_id: Kernel.timer_t,
) c_long;
pub const clock_settime = fn (
    which_clock: Kernel.clockid_t,
    tp: *Kernel.__kernel_timespec,
) c_long;
pub const clock_gettime = fn (
    which_clock: Kernel.clockid_t,
    tp: *Kernel.__kernel_timespec,
) c_long;
pub const clock_getres = fn (
    which_clock: Kernel.clockid_t,
    tp: *Kernel.__kernel_timespec,
) c_long;
pub const clock_nanosleep = fn (
    which_clock: Kernel.clockid_t,
    flags: Kernel.int,
    rqtp: *Kernel.__kernel_timespec,
    rmtp: *Kernel.__kernel_timespec,
) c_long;
pub const exit_group = fn (
    error_code: Kernel.int,
) c_long;
pub const epoll_wait = fn (
    epfd: Kernel.int,
    events: *Kernel.epoll_event,
    maxevents: Kernel.int,
    timeout: Kernel.int,
) c_long;
pub const epoll_ctl = fn (
    epfd: Kernel.int,
    op: Kernel.int,
    fd: Kernel.int,
    event: *Kernel.epoll_event,
) c_long;
pub const tgkill = fn (
    tgid: Kernel.pid_t,
    pid: Kernel.pid_t,
    sig: Kernel.int,
) c_long;
pub const utimes = fn (
    filename: *Kernel.char,
    utimes: *Kernel.__kernel_old_timeval,
) c_long;
pub const mbind = fn (
    start: c_ulong,
    len: c_ulong,
    mode: c_ulong,
    nmask: *c_ulong,
    maxnode: c_ulong,
    flags: Kernel.unsigned_int,
) c_long;
pub const set_mempolicy = fn (
    mode: Kernel.int,
    nmask: *c_ulong,
    maxnode: c_ulong,
) c_long;
pub const get_mempolicy = fn (
    policy: *Kernel.int,
    nmask: *c_ulong,
    maxnode: c_ulong,
    addr: c_ulong,
    flags: c_ulong,
) c_long;
pub const mq_open = fn (
    u_name: *Kernel.char,
    oflag: Kernel.int,
    mode: Kernel.umode_t,
    u_attr: *Kernel.mq_attr,
) c_long;
pub const mq_unlink = fn (
    u_name: *Kernel.char,
) c_long;
pub const mq_timedsend = fn (
    mqdes: Kernel.mqd_t,
    u_msg_ptr: *Kernel.char,
    msg_len: Kernel.size_t,
    msg_prio: Kernel.unsigned_int,
    u_abs_timeout: *Kernel.__kernel_timespec,
) c_long;
pub const mq_timedreceive = fn (
    mqdes: Kernel.mqd_t,
    u_msg_ptr: *Kernel.char,
    msg_len: Kernel.size_t,
    u_msg_prio: *Kernel.unsigned_int,
    u_abs_timeout: *Kernel.__kernel_timespec,
) c_long;
pub const mq_notify = fn (
    mqdes: Kernel.mqd_t,
    u_notification: *Kernel.sigevent,
) c_long;
pub const mq_getsetattr = fn (
    mqdes: Kernel.mqd_t,
    u_mqstat: *Kernel.mq_attr,
    u_omqstat: *Kernel.mq_attr,
) c_long;
pub usingnamespace if (@hasDecl(Kernel, "kexec_segment")) struct {
    pub const kexec_load = fn (
        entry: c_ulong,
        nr_segments: c_ulong,
        segments: *Kernel.kexec_segment,
        flags: c_ulong,
    ) c_long;
} else struct {};
pub const waitid = fn (
    which: Kernel.int,
    upid: Kernel.pid_t,
    infop: *Kernel.siginfo,
    options: Kernel.int,
    ru: *Kernel.rusage,
) c_long;
pub const add_key = fn (
    _type: *Kernel.char,
    _description: *Kernel.char,
    _payload: *Kernel.void,
    plen: Kernel.size_t,
    ringid: Kernel.key_serial_t,
) c_long;
pub const request_key = fn (
    _type: *Kernel.char,
    _description: *Kernel.char,
    _callout_info: *Kernel.char,
    destringid: Kernel.key_serial_t,
) c_long;
pub const keyctl = fn (
    option: Kernel.int,
    arg2: c_ulong,
    arg3: c_ulong,
    arg4: c_ulong,
    arg5: c_ulong,
) c_long;
pub const ioprio_set = fn (
    which: Kernel.int,
    who: Kernel.int,
    ioprio: Kernel.int,
) c_long;
pub const ioprio_get = fn (
    which: Kernel.int,
    who: Kernel.int,
) c_long;
pub const inotify_init = fn () c_long;
pub const inotify_add_watch = fn (
    fd: Kernel.int,
    pathname: *Kernel.char,
    mask: Kernel.u32,
) c_long;
pub const inotify_rm_watch = fn (
    fd: Kernel.int,
    wd: Kernel.__s32,
) c_long;
pub const migrate_pages = fn (
    pid: Kernel.pid_t,
    maxnode: c_ulong,
    old_nodes: *c_ulong,
    new_nodes: *c_ulong,
) c_long;
pub const openat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    flags: Kernel.int,
    mode: Kernel.umode_t,
) c_long;
pub const mkdirat = fn (
    dfd: Kernel.int,
    pathname: *Kernel.char,
    mode: Kernel.umode_t,
) c_long;
pub const mknodat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    mode: Kernel.umode_t,
    dev: Kernel.unsigned_int,
) c_long;
pub const fchownat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    user: Kernel.uid_t,
    group: Kernel.gid_t,
    flag: Kernel.int,
) c_long;
pub const futimesat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    utimes: *Kernel.__kernel_old_timeval,
) c_long;
pub const newfstatat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    statbuf: *Kernel.stat,
    flag: Kernel.int,
) c_long;
pub const unlinkat = fn (
    dfd: Kernel.int,
    pathname: *Kernel.char,
    flag: Kernel.int,
) c_long;
pub const renameat = fn (
    olddfd: Kernel.int,
    oldname: *Kernel.char,
    newdfd: Kernel.int,
    newname: *Kernel.char,
) c_long;
pub const linkat = fn (
    olddfd: Kernel.int,
    oldname: *Kernel.char,
    newdfd: Kernel.int,
    newname: *Kernel.char,
    flags: Kernel.int,
) c_long;
pub const symlinkat = fn (
    oldname: *Kernel.char,
    newdfd: Kernel.int,
    newname: *Kernel.char,
) c_long;
pub const readlinkat = fn (
    dfd: Kernel.int,
    pathname: *Kernel.char,
    buf: *Kernel.char,
    bufsiz: Kernel.int,
) c_long;
pub const fchmodat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    mode: Kernel.umode_t,
) c_long;
pub const faccessat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    mode: Kernel.int,
) c_long;
pub const pselect6 = fn (
    n: Kernel.int,
    inp: *Kernel.fd_set,
    outp: *Kernel.fd_set,
    exp: *Kernel.fd_set,
    tsp: *Kernel.__kernel_timespec,
    sig: *Kernel.void,
) c_long;
pub const ppoll = fn (
    ufds: *Kernel.pollfd,
    nfds: Kernel.unsigned_int,
    tsp: *Kernel.__kernel_timespec,
    sigmask: *Kernel.sigset_t,
    sigsetsize: Kernel.size_t,
) c_long;
pub const unshare = fn (
    unshare_flags: c_ulong,
) c_long;
pub const set_robust_list = fn (
    head: *Kernel.robust_list_head,
    len: Kernel.size_t,
) c_long;
pub const get_robust_list = fn (
    pid: Kernel.int,
    head_ptr: **Kernel.robust_list_head,
    len_ptr: *Kernel.size_t,
) c_long;
pub const splice = fn (
    fd_in: Kernel.int,
    off_in: *Kernel.loff_t,
    fd_out: Kernel.int,
    off_out: *Kernel.loff_t,
    len: Kernel.size_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const tee = fn (
    fdin: Kernel.int,
    fdout: Kernel.int,
    len: Kernel.size_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const sync_file_range = fn (
    fd: Kernel.int,
    offset: Kernel.loff_t,
    nbytes: Kernel.loff_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const vmsplice = fn (
    fd: Kernel.int,
    uiov: *Kernel.iovec,
    nr_segs: c_ulong,
    flags: Kernel.unsigned_int,
) c_long;
pub const move_pages = fn (
    pid: Kernel.pid_t,
    nr_pages: c_ulong,
    pages: **Kernel.void,
    nodes: *Kernel.int,
    status: *Kernel.int,
    flags: Kernel.int,
) c_long;
pub const utimensat = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    utimes: *Kernel.__kernel_timespec,
    flags: Kernel.int,
) c_long;
pub const epoll_pwait = fn (
    epfd: Kernel.int,
    events: *Kernel.epoll_event,
    maxevents: Kernel.int,
    timeout: Kernel.int,
    sigmask: *Kernel.sigset_t,
    sigsetsize: Kernel.size_t,
) c_long;
pub const signalfd = fn (
    ufd: Kernel.int,
    user_mask: *Kernel.sigset_t,
    sizemask: Kernel.size_t,
) c_long;
pub const timerfd_create = fn (
    clockid: Kernel.int,
    flags: Kernel.int,
) c_long;
pub const eventfd = fn (
    count: Kernel.unsigned_int,
) c_long;
pub const fallocate = fn (
    fd: Kernel.int,
    mode: Kernel.int,
    offset: Kernel.loff_t,
    len: Kernel.loff_t,
) c_long;
pub const timerfd_settime = fn (
    ufd: Kernel.int,
    flags: Kernel.int,
    utmr: *Kernel.__kernel_itimerspec,
    otmr: *Kernel.__kernel_itimerspec,
) c_long;
pub const timerfd_gettime = fn (
    ufd: Kernel.int,
    otmr: *Kernel.__kernel_itimerspec,
) c_long;
pub const accept4 = fn (
    fd: Kernel.int,
    upeer_sockaddr: *Kernel.sockaddr,
    upeer_addrlen: *Kernel.int,
    flags: Kernel.int,
) c_long;
pub const signalfd4 = fn (
    ufd: Kernel.int,
    user_mask: *Kernel.sigset_t,
    sizemask: Kernel.size_t,
    flags: Kernel.int,
) c_long;
pub const eventfd2 = fn (
    count: Kernel.unsigned_int,
    flags: Kernel.int,
) c_long;
pub const epoll_create1 = fn (
    flags: Kernel.int,
) c_long;
pub const dup3 = fn (
    oldfd: Kernel.unsigned_int,
    newfd: Kernel.unsigned_int,
    flags: Kernel.int,
) c_long;
pub const pipe2 = fn (
    fildes: *Kernel.int,
    flags: Kernel.int,
) c_long;
pub const inotify_init1 = fn (
    flags: Kernel.int,
) c_long;
pub const preadv = fn (
    fd: c_ulong,
    vec: *Kernel.iovec,
    vlen: c_ulong,
    pos_l: c_ulong,
    pos_h: c_ulong,
) c_long;
pub const pwritev = fn (
    fd: c_ulong,
    vec: *Kernel.iovec,
    vlen: c_ulong,
    pos_l: c_ulong,
    pos_h: c_ulong,
) c_long;
pub const rt_tgsigqueueinfo = fn (
    tgid: Kernel.pid_t,
    pid: Kernel.pid_t,
    sig: Kernel.int,
    uinfo: *Kernel.siginfo_t,
) c_long;
pub const perf_event_open = fn (
    attr_uptr: *Kernel.perf_event_attr,
    pid: Kernel.pid_t,
    cpu: Kernel.int,
    group_fd: Kernel.int,
    flags: c_ulong,
) c_long;
pub const recvmmsg = fn (
    fd: Kernel.int,
    mmsg: *Kernel.mmsghdr,
    vlen: Kernel.unsigned_int,
    flags: Kernel.unsigned_int,
    timeout: *Kernel.__kernel_timespec,
) c_long;
pub const fanotify_init = fn (
    flags: Kernel.unsigned_int,
    event_f_flags: Kernel.unsigned_int,
) c_long;
pub const fanotify_mark = fn (
    fanotify_fd: Kernel.int,
    flags: Kernel.unsigned_int,
    mask: Kernel.__u64,
    dfd: Kernel.int,
    pathname: *Kernel.char,
) c_long;
pub const prlimit64 = fn (
    pid: Kernel.pid_t,
    resource: Kernel.unsigned_int,
    new_rlim: *Kernel.rlimit64,
    old_rlim: *Kernel.rlimit64,
) c_long;
pub const name_to_handle_at = fn (
    dfd: Kernel.int,
    name: *Kernel.char,
    handle: *Kernel.file_handle,
    mnt_id: *Kernel.void,
    flag: Kernel.int,
) c_long;
pub const open_by_handle_at = fn (
    mountdirfd: Kernel.int,
    handle: *Kernel.file_handle,
    flags: Kernel.int,
) c_long;
pub const clock_adjtime = fn (
    which_clock: Kernel.clockid_t,
    utx: *Kernel.__kernel_timex,
) c_long;
pub const syncfs = fn (
    fd: Kernel.int,
) c_long;
pub const sendmmsg = fn (
    fd: Kernel.int,
    mmsg: *Kernel.mmsghdr,
    vlen: Kernel.unsigned_int,
    flags: Kernel.unsigned_int,
) c_long;
pub const setns = fn (
    fd: Kernel.int,
    flags: Kernel.int,
) c_long;
pub const getcpu = fn (
    cpup: *unsigned_int,
    nodep: *unsigned_int,
    unused: *Kernel.getcpu_cache,
) c_long;
pub const process_vm_readv = fn (
    pid: Kernel.pid_t,
    lvec: *Kernel.iovec,
    liovcnt: c_ulong,
    rvec: *Kernel.iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) c_long;
pub const process_vm_writev = fn (
    pid: Kernel.pid_t,
    lvec: *Kernel.iovec,
    liovcnt: c_ulong,
    rvec: *Kernel.iovec,
    riovcnt: c_ulong,
    flags: c_ulong,
) c_long;
pub const kcmp = fn (
    pid1: Kernel.pid_t,
    pid2: Kernel.pid_t,
    type: Kernel.int,
    idx1: c_ulong,
    idx2: c_ulong,
) c_long;
pub const finit_module = fn (
    fd: Kernel.int,
    uargs: *Kernel.char,
    flags: Kernel.int,
) c_long;
pub const sched_setattr = fn (
    pid: Kernel.pid_t,
    uattr: *Kernel.sched_attr,
    flags: Kernel.unsigned_int,
) c_long;
pub const sched_getattr = fn (
    pid: Kernel.pid_t,
    uattr: *Kernel.sched_attr,
    usize: Kernel.unsigned_int,
    flags: Kernel.unsigned_int,
) c_long;
pub const renameat2 = fn (
    olddfd: Kernel.int,
    oldname: *Kernel.char,
    newdfd: Kernel.int,
    newname: *Kernel.char,
    flags: Kernel.unsigned_int,
) c_long;
pub const seccomp = fn (
    op: Kernel.unsigned_int,
    flags: Kernel.unsigned_int,
    uargs: *Kernel.void,
) c_long;
pub const getrandom = fn (
    ubuf: *Kernel.char,
    len: Kernel.size_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const memfd_create = fn (
    uname: *Kernel.char,
    flags: Kernel.unsigned_int,
) c_long;
pub const kexec_file_load = fn (
    kernel_fd: Kernel.int,
    initrd_fd: Kernel.int,
    cmdline_len: c_ulong,
    cmdline_ptr: *Kernel.char,
    flags: c_ulong,
) c_long;
pub const bpf = fn (
    cmd: Kernel.int,
    uattr: *Kernel.bpf_attr,
    size: Kernel.unsigned_int,
) c_long;
pub const execveat = fn (
    fd: Kernel.int,
    filename: *Kernel.char,
    argv: **Kernel.char,
    envp: **Kernel.char,
    flags: Kernel.int,
) c_long;
pub const userfaultfd = fn (
    flags: Kernel.int,
) c_long;
pub const membarrier = fn (
    cmd: Kernel.int,
    flags: Kernel.unsigned_int,
    cpu_id: Kernel.int,
) c_long;
pub const mlock2 = fn (
    start: c_ulong,
    len: Kernel.size_t,
    flags: Kernel.int,
) c_long;
pub const copy_file_range = fn (
    fd_in: Kernel.int,
    off_in: *Kernel.loff_t,
    fd_out: Kernel.int,
    off_out: *Kernel.loff_t,
    len: Kernel.size_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const preadv2 = fn (
    fd: c_ulong,
    vec: *Kernel.iovec,
    vlen: c_ulong,
    pos_l: c_ulong,
    pos_h: c_ulong,
    flags: Kernel.rwf_t,
) c_long;
pub const pwritev2 = fn (
    fd: c_ulong,
    vec: *Kernel.iovec,
    vlen: c_ulong,
    pos_l: c_ulong,
    pos_h: c_ulong,
    flags: Kernel.rwf_t,
) c_long;
pub const pkey_mprotect = fn (
    start: c_ulong,
    len: Kernel.size_t,
    prot: c_ulong,
    pkey: Kernel.int,
) c_long;
pub const pkey_alloc = fn (
    flags: c_ulong,
    init_val: c_ulong,
) c_long;
pub const pkey_free = fn (
    pkey: Kernel.int,
) c_long;
pub const statx = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    flags: unsigned_int,
    mask: Kernel.unsigned_int,
    buffer: *Kernel.statx,
) c_long;
pub const io_pgetevents = fn (
    ctx_id: Kernel.aio_context_t,
    min_nr: long_int,
    nr: long_int,
    events: *Kernel.io_event,
    timeout: *Kernel.__kernel_timespec,
    usig: *Kernel.__aio_sigset,
) c_long;
pub const rseq = fn (
    rseq: *Kernel.rseq,
    rseq_len: Kernel.u32,
    flags: Kernel.int,
    sig: Kernel.u32,
) c_long;
pub const uretprobe = fn () c_long;
pub const pidfd_send_signal = fn (
    pidfd: Kernel.int,
    sig: Kernel.int,
    info: *Kernel.siginfo_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const io_uring_setup = fn (
    entries: Kernel.u32,
    params: *Kernel.io_uring_params,
) c_long;
pub const io_uring_enter = fn (
    fd: Kernel.unsigned_int,
    to_submit: Kernel.u32,
    min_complete: Kernel.u32,
    flags: Kernel.u32,
    argp: *Kernel.void,
    argsz: Kernel.size_t,
) c_long;
pub const io_uring_register = fn (
    fd: Kernel.unsigned_int,
    opcode: Kernel.unsigned_int,
    arg: *Kernel.void,
    nr_args: Kernel.unsigned_int,
) c_long;
pub const open_tree = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    flags: unsigned_int,
) c_long;
pub const move_mount = fn (
    from_dfd: Kernel.int,
    from_pathname: *Kernel.char,
    to_dfd: Kernel.int,
    to_pathname: *Kernel.char,
    flags: Kernel.unsigned_int,
) c_long;
pub const fsopen = fn (
    _fs_name: *Kernel.char,
    flags: Kernel.unsigned_int,
) c_long;
pub const fsconfig = fn (
    fd: Kernel.int,
    cmd: Kernel.unsigned_int,
    _key: *Kernel.char,
    _value: *Kernel.void,
    aux: Kernel.int,
) c_long;
pub const fsmount = fn (
    fs_fd: Kernel.int,
    flags: Kernel.unsigned_int,
    attr_flags: Kernel.unsigned_int,
) c_long;
pub const fspick = fn (
    dfd: Kernel.int,
    path: *Kernel.char,
    flags: Kernel.unsigned_int,
) c_long;
pub const pidfd_open = fn (
    pid: Kernel.pid_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const clone3 = fn (
    uargs: *Kernel.clone_args,
    size: Kernel.size_t,
) c_long;
pub const close_range = fn (
    fd: Kernel.unsigned_int,
    max_fd: Kernel.unsigned_int,
    flags: Kernel.unsigned_int,
) c_long;
pub const openat2 = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    how: *Kernel.open_how,
    usize: Kernel.size_t,
) c_long;
pub const pidfd_getfd = fn (
    pidfd: Kernel.int,
    fd: Kernel.int,
    flags: Kernel.unsigned_int,
) c_long;
pub const faccessat2 = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    mode: Kernel.int,
    flags: Kernel.int,
) c_long;
pub const process_madvise = fn (
    pidfd: Kernel.int,
    vec: *Kernel.iovec,
    vlen: Kernel.size_t,
    behavior: Kernel.int,
    flags: Kernel.unsigned_int,
) c_long;
pub const epoll_pwait2 = fn (
    epfd: Kernel.int,
    events: *Kernel.epoll_event,
    maxevents: Kernel.int,
    timeout: *Kernel.__kernel_timespec,
    sigmask: *Kernel.sigset_t,
    sigsetsize: Kernel.size_t,
) c_long;
pub usingnamespace if (@hasDecl(Kernel, "mount_attr")) struct {
    pub const mount_setattr = fn (
        dfd: Kernel.int,
        path: *Kernel.char,
        flags: Kernel.unsigned_int,
        uattr: *Kernel.mount_attr,
        usize: Kernel.size_t,
    ) c_long;
} else struct {};
pub const quotactl_fd = fn (
    fd: Kernel.unsigned_int,
    cmd: Kernel.unsigned_int,
    id: Kernel.qid_t,
    addr: *Kernel.void,
) c_long;
pub usingnamespace if (@hasDecl(Kernel, "landlock_ruleset_attr")) struct {
    pub const landlock_create_ruleset = fn (
        attr: *Kernel.landlock_ruleset_attr,
        size: Kernel.size_t,
        flags: Kernel.__u32,
    ) c_long;
    pub const landlock_add_rule = fn (
        ruleset_fd: Kernel.int,
        rule_type: Kernel.landlock_rule_type,
        rule_attr: *Kernel.void,
        flags: Kernel.__u32,
    ) c_long;
    pub const landlock_restrict_self = fn (
        ruleset_fd: Kernel.int,
        flags: Kernel.__u32,
    ) c_long;
} else struct {};
pub const memfd_secret = fn (
    flags: Kernel.unsigned_int,
) c_long;
pub const process_mrelease = fn (
    pidfd: Kernel.int,
    flags: Kernel.unsigned_int,
) c_long;
pub const set_mempolicy_home_node = fn (
    start: c_ulong,
    len: c_ulong,
    home_node: c_ulong,
    flags: c_ulong,
) c_long;
pub usingnamespace if (@hasDecl(Kernel, "cachestat_range")) struct {
    pub const cachestat = fn (
        fd: Kernel.unsigned_int,
        cstat_range: *Kernel.cachestat_range,
        cstat: *Kernel.cachestat,
        flags: Kernel.unsigned_int,
    ) c_long;
} else struct {};
pub const fchmodat2 = fn (
    dfd: Kernel.int,
    filename: *Kernel.char,
    mode: Kernel.umode_t,
    flags: Kernel.unsigned_int,
) c_long;
pub const map_shadow_stack = fn (
    addr: c_ulong,
    size: c_ulong,
    flags: Kernel.unsigned_int,
) c_long;
pub const futex_wake = fn (
    uaddr: *Kernel.void,
    mask: c_ulong,
    nr: Kernel.int,
    flags: Kernel.unsigned_int,
) c_long;
pub const futex_wait = fn (
    uaddr: *Kernel.void,
    val: c_ulong,
    mask: c_ulong,
    flags: Kernel.unsigned_int,
    timeout: *Kernel.__kernel_timespec,
    clockid: Kernel.clockid_t,
) c_long;
pub usingnamespace if (@hasDecl(Kernel, "futex_waitv")) struct {
    pub const futex_waitv = fn (
        waiters: *Kernel.futex_waitv,
        nr_futexes: Kernel.unsigned_int,
        flags: Kernel.unsigned_int,
        timeout: *Kernel.__kernel_timespec,
        clockid: Kernel.clockid_t,
    ) c_long;
    pub const futex_requeue = fn (
        waiters: *Kernel.futex_waitv,
        flags: Kernel.unsigned_int,
        nr_wake: Kernel.int,
        nr_requeue: Kernel.int,
    ) c_long;
} else struct {};
pub usingnamespace if (@hasDecl(Kernel, "mnt_id_req")) struct {
    pub const statmount = fn (
        req: *Kernel.mnt_id_req,
        buf: *Kernel.statmount,
        bufsize: Kernel.size_t,
        flags: Kernel.unsigned_int,
    ) c_long;
    pub const listmount = fn (
        req: *Kernel.mnt_id_req,
        mnt_ids: *Kernel.u64,
        nr_mnt_ids: Kernel.size_t,
        flags: Kernel.unsigned_int,
    ) c_long;
} else struct {};
pub usingnamespace if (@hasDecl(Kernel, "lsm_ctx")) struct {
    pub const lsm_get_self_attr = fn (
        attr: Kernel.unsigned_int,
        ctx: *Kernel.lsm_ctx,
        size: *Kernel.u32,
        flags: Kernel.u32,
    ) c_long;
    pub const lsm_set_self_attr = fn (
        attr: Kernel.unsigned_int,
        ctx: *Kernel.lsm_ctx,
        size: Kernel.u32,
        flags: Kernel.u32,
    ) c_long;
} else struct {};
pub const lsm_list_modules = fn (
    ids: *Kernel.u64,
    size: *Kernel.u32,
    flags: Kernel.u32,
) c_long;
pub const mseal = fn (
    start: c_ulong,
    len: Kernel.size_t,
    flags: c_ulong,
) c_long;
