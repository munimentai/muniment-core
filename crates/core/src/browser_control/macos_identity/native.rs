use super::{
    ExecutableIdentity, MacOsProcessReader, NativeProcessReader, ProcessReadError, ProcessSocket,
};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_char, c_int, c_void};

// Values exported by the macOS SDK's <libproc.h> and <sys/proc_info.h>.
const PROC_UID_ONLY: u32 = 4;
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROC_PIDREGIONPATHINFO: c_int = 8;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_TCP: i32 = 2;
const AF_INET: i32 = 2;
const AF_INET6: i32 = 30;
const INI_IPV4: u8 = 1;
const INI_IPV6: u8 = 2;
const BSD_INFO_SIZE: usize = 136;
// `sizeof(struct socket_fdinfo)` in the macOS SDK. The large tail is the
// `socket_info.soi_proto` union (not merely its TCP member).
const SOCKET_INFO_SIZE: usize = 792;

const _: () = assert!(PROC_UID_ONLY == 4);
const _: () = assert!(PROC_PIDLISTFDS == 1);
const _: () = assert!(PROC_PIDTBSDINFO == 3);
const _: () = assert!(PROC_PIDFDSOCKETINFO == 3);
const _: () = assert!(PROC_PIDREGIONPATHINFO == 8);

#[repr(C)]
struct ProcRegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    obj_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[repr(C)]
struct ProcRegionWithPathInfo {
    region: ProcRegionInfo,
    vnode: libc::vnode_info_path,
}

#[link(name = "proc")]
extern "C" {
    fn proc_listpids(kind: u32, typeinfo: u32, buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

impl NativeProcessReader for MacOsProcessReader {
    fn process_ids(&self) -> Result<Vec<u32>, ProcessReadError> {
        let uid = unsafe { libc::geteuid() };
        let needed = unsafe { proc_listpids(PROC_UID_ONLY, uid, std::ptr::null_mut(), 0) };
        if needed <= 0 {
            return Err(ProcessReadError);
        }
        // Leave room for processes created between sizing and reading. A full
        // buffer is rejected because it may represent a truncated owner set.
        let mut pids = vec![0u32; needed as usize / size_of::<u32>() + 64];
        let capacity = (pids.len() * size_of::<u32>())
            .try_into()
            .map_err(|_| ProcessReadError)?;
        let read = unsafe { proc_listpids(PROC_UID_ONLY, uid, pids.as_mut_ptr().cast(), capacity) };
        if read <= 0 || read == capacity || read as usize % size_of::<u32>() != 0 {
            return Err(ProcessReadError);
        }
        pids.truncate(read as usize / size_of::<u32>());
        pids.retain(|pid| *pid != 0);
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    fn start_identity(&self, pid: u32) -> Result<(u64, u64), ProcessReadError> {
        let mut bytes = [0u8; BSD_INFO_SIZE];
        let read = unsafe {
            proc_pidinfo(
                pid.try_into().map_err(|_| ProcessReadError)?,
                PROC_PIDTBSDINFO,
                0,
                bytes.as_mut_ptr().cast(),
                BSD_INFO_SIZE as c_int,
            )
        };
        if read != BSD_INFO_SIZE as c_int {
            return Err(ProcessReadError);
        }
        Ok((read_u64(&bytes, 120)?, read_u64(&bytes, 128)?))
    }

    fn executable_identity(&self, pid: u32) -> Result<ExecutableIdentity, ProcessReadError> {
        let pid = pid.try_into().map_err(|_| ProcessReadError)?;
        let mut address = 0;
        // The first region can be an anonymous __PAGEZERO mapping. The first
        // file-backed mapping is the process image; keep this walk bounded and
        // reject malformed or unexpectedly fragmented maps.
        for _ in 0..256 {
            let mut info = std::mem::MaybeUninit::<ProcRegionWithPathInfo>::zeroed();
            let read = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDREGIONPATHINFO,
                    address,
                    info.as_mut_ptr().cast(),
                    size_of::<ProcRegionWithPathInfo>() as c_int,
                )
            };
            if read != size_of::<ProcRegionWithPathInfo>() as c_int {
                return Err(ProcessReadError);
            }
            let info = unsafe { info.assume_init() };
            let stat = info.vnode.vip_vi.vi_stat;
            if stat.vst_dev != 0 && stat.vst_ino != 0 {
                return Ok(ExecutableIdentity {
                    device: stat.vst_dev.into(),
                    inode: stat.vst_ino,
                });
            }
            address = info
                .region
                .address
                .checked_add(info.region.size)
                .filter(|next| *next > address)
                .ok_or(ProcessReadError)?;
        }
        Err(ProcessReadError)
    }

    fn tcp_sockets(&self, pid: u32) -> Result<Vec<ProcessSocket>, ProcessReadError> {
        let pid: c_int = pid.try_into().map_err(|_| ProcessReadError)?;
        let needed = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if needed < 0 || needed as usize % 8 != 0 {
            return Err(ProcessReadError);
        }
        let mut fds = vec![0u8; needed as usize + 8 * 64];
        let capacity: c_int = fds.len().try_into().map_err(|_| ProcessReadError)?;
        let read =
            unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.as_mut_ptr().cast(), capacity) };
        if read < 0 || read == capacity || read as usize % 8 != 0 {
            return Err(ProcessReadError);
        }
        let mut sockets = Vec::new();
        for fd in fds[..read as usize].chunks_exact(8) {
            if read_u32(fd, 4)? != PROX_FDTYPE_SOCKET {
                continue;
            }
            let descriptor = i32::from_ne_bytes(fd[..4].try_into().unwrap());
            let mut info = [0u8; SOCKET_INFO_SIZE];
            let info_read = unsafe {
                proc_pidfdinfo(
                    pid,
                    descriptor,
                    PROC_PIDFDSOCKETINFO,
                    info.as_mut_ptr().cast(),
                    SOCKET_INFO_SIZE as c_int,
                )
            };
            if info_read != SOCKET_INFO_SIZE as c_int {
                return Err(ProcessReadError);
            }
            if read_i32(&info, 256)? != SOCKINFO_TCP {
                continue;
            }
            if let Some(socket) = parse_tcp_socket(&info)? {
                sockets.push(socket);
            }
        }
        Ok(sockets)
    }
}

fn parse_tcp_socket(bytes: &[u8]) -> Result<Option<ProcessSocket>, ProcessReadError> {
    let family = read_i32(bytes, 184)?;
    let flags = *bytes.get(288).ok_or(ProcessReadError)?;
    let peer_port =
        u16::from_be_bytes(read_i32(bytes, 264)?.to_ne_bytes()[..2].try_into().unwrap());
    let local_port =
        u16::from_be_bytes(read_i32(bytes, 268)?.to_ne_bytes()[..2].try_into().unwrap());
    let (local_ip, peer_ip) = match (family, flags) {
        (AF_INET, INI_IPV4) => (
            Ipv4Addr::from(read_array::<4>(bytes, 324)?).into(),
            Ipv4Addr::from(read_array::<4>(bytes, 308)?).into(),
        ),
        (AF_INET6, INI_IPV6) => (
            Ipv6Addr::from(read_array::<16>(bytes, 312)?).into(),
            Ipv6Addr::from(read_array::<16>(bytes, 296)?).into(),
        ),
        _ => return Ok(None),
    };
    if local_port == 0 || peer_port == 0 {
        return Ok(None);
    }
    Ok(Some(ProcessSocket {
        local: SocketAddr::new(local_ip, local_port),
        peer: SocketAddr::new(peer_ip, peer_port),
    }))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProcessReadError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(ProcessReadError)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ProcessReadError> {
    Ok(u32::from_ne_bytes(read_array(bytes, offset)?))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, ProcessReadError> {
    Ok(i32::from_ne_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ProcessReadError> {
    Ok(u64::from_ne_bytes(read_array(bytes, offset)?))
}
