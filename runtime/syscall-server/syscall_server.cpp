#include "syscall_server.hpp"
#include "bpftime_shm.hpp"
#include "handler/perf_event_handler.hpp"
#include "linux/bpf.h"
#include "spdlog/cfg/env.h"
#include <asm-generic/errno-base.h>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <ranges>
#include <spdlog/spdlog.h>
#include <string_view>
#include <unistd.h>
#ifdef ENABLE_BPFTIME_VERIFIER
#include <bpftime-verifier.hpp>
#include <iomanip>
#include <sstream>
#endif

#include <sys/epoll.h>
#include <spdlog/cfg/env.h>
using namespace bpftime;

const shm_open_type bpftime::global_shm_open_type = shm_open_type::SHM_SERVER;

// global context for bpf syscall server
static syscall_context context;

#define PERF_UPROBE_REF_CTR_OFFSET_BITS 32
#define PERF_UPROBE_REF_CTR_OFFSET_SHIFT 32

static bool already_setup = false;

static void start_up()
{
	if (already_setup)
		return;
	spdlog::cfg::load_env_levels();
	spdlog::set_pattern("[%Y-%m-%d %H:%M:%S][%^%l%$][%t] %v");
	auto &agent_config = bpftime_get_agent_config();
	if (const char *custom_helpers = getenv("BPFTIME_HELPER_GROUPS");
	    custom_helpers != nullptr) {
		agent_config.enable_kernel_helper_group =
			agent_config.enable_ffi_helper_group =
				agent_config.enable_shm_maps_helper_group =
					false;
		auto helpers_sv = std::string_view(custom_helpers);
		for (auto tok : helpers_sv | std::ranges::views::split(
						     std::string_view(","))) {
			auto curr_token =
				std::string_view(tok.begin(), tok.end());
			if (curr_token == "ffi") {
				spdlog::info("Enabling ffi helper group");
				agent_config.enable_ffi_helper_group = true;
			} else if (curr_token == "kernel") {
				spdlog::info("Enabling kernel helper group");
				agent_config.enable_kernel_helper_group = true;
			} else if (curr_token == "shm_map") {
				spdlog::info("Enabling shm_map helper group");
				agent_config.enable_shm_maps_helper_group =
					true;
			} else {
				spdlog::warn("Unknown helper group: {}",
					     curr_token);
			}
		}
	} else {
		spdlog::info(
			"Enabling helper groups ffi, kernel, shm_map by default");
		agent_config.enable_kernel_helper_group =
			agent_config.enable_shm_maps_helper_group =
				agent_config.enable_ffi_helper_group = true;
	}
#ifdef ENABLE_BPFTIME_VERIFIER
	std::vector<int32_t> helper_ids;
	std::map<int32_t, bpftime::verifier::BpftimeHelperProrotype>
		non_kernel_helpers;
	if (agent_config.enable_kernel_helper_group) {
		for (auto x :
		     bpftime_helper_group::get_kernel_utils_helper_group()
			     .get_helper_ids()) {
			helper_ids.push_back(x);
		}
	}
	if (agent_config.enable_shm_maps_helper_group) {
		for (auto x : bpftime_helper_group::get_shm_maps_helper_group()
				      .get_helper_ids()) {
			helper_ids.push_back(x);
		}
	}
	if (agent_config.enable_ffi_helper_group) {
		for (auto x : bpftime_helper_group::get_shm_maps_helper_group()
				      .get_helper_ids()) {
			helper_ids.push_back(x);
		}
		// non_kernel_helpers =
		for (const auto &[k, v] : get_ffi_helper_protos()) {
			non_kernel_helpers[k] = v;
		}
	}
	verifier::set_available_helpers(helper_ids);
	spdlog::info("Enabling {} helpers", helper_ids.size());
	verifier::set_non_kernel_helpers(non_kernel_helpers);
#endif
	already_setup = true;
}

/*
 * this function is expected to parse integer in the range of [0, 2^31-1] from
 * given file using scanf format string fmt. If actual parsed value is
 * negative, the result might be indistinguishable from error
 */
static int parse_uint_from_file(const char *file, const char *fmt)
{
	int err, ret;
	FILE *f;

	f = fopen(file, "re");
	if (!f) {
		err = -errno;
		spdlog::error("Failed to open {}: {}", file, err);
		return err;
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
	err = fscanf(f, fmt, &ret);
#pragma GCC diagnostic pop
	if (err != 1) {
		err = err == EOF ? -EIO : -errno;
		spdlog::error("Failed to parse {}: {}", file, err);
		fclose(f);
		return err;
	}
	fclose(f);
	return ret;
}

static int determine_uprobe_perf_type(void)
{
	const char *file = "/sys/bus/event_source/devices/uprobe/type";

	return parse_uint_from_file(file, "%d\n");
}

static int determine_uprobe_retprobe_bit(void)
{
	const char *file =
		"/sys/bus/event_source/devices/uprobe/format/retprobe";

	return parse_uint_from_file(file, "config:%d\n");
}

extern "C" int epoll_wait(int epfd, epoll_event *evt, int maxevents,
			  int timeout)
{
	spdlog::debug("epoll_wait {}", epfd);
	return context.handle_epoll_wait(epfd, evt, maxevents, timeout);
}

extern "C" int epoll_ctl(int epfd, int op, int fd, epoll_event *evt)
{
	spdlog::debug("epoll_ctl {} {} {} {}", epfd, op, fd, (uintptr_t)evt);
	return context.handle_epoll_ctl(epfd, op, fd, evt);
}

extern "C" int epoll_create1(int flags)
{
	spdlog::debug("epoll_create1 {}", flags);
	return context.handle_epoll_create1(flags);
}

extern "C" int ioctl(int fd, unsigned long req, int data)
{
	spdlog::debug("ioctl {} {} {}", fd, req, data);
	return context.handle_ioctl(fd, req, data);
}

extern "C" void *mmap64(void *addr, size_t length, int prot, int flags, int fd,
			off64_t offset)
{
	spdlog::debug("mmap64 {:x}", (uintptr_t)addr);
	return context.handle_mmap64(addr, length, prot, flags, fd, offset);
}

extern "C" int close(int fd)
{
	spdlog::debug("Closing {}", fd);
	return context.handle_close(fd);
}

extern "C" long syscall(long sysno, ...)
{
	// glibc directly reads the arguments without considering
	// the underlying argument number. So did us
	va_list args;
	va_start(args, sysno);
	long arg1 = va_arg(args, long);
	long arg2 = va_arg(args, long);
	long arg3 = va_arg(args, long);
	long arg4 = va_arg(args, long);
	long arg5 = va_arg(args, long);
	long arg6 = va_arg(args, long);
	va_end(args);
	if (sysno == __NR_bpf) {
		spdlog::debug("SYS_BPF {} {} {} {} {} {}", arg1, arg2, arg3,
			      arg4, arg5, arg6);
		int cmd = (int)arg1;
		auto attr = (union bpf_attr *)(uintptr_t)arg2;
		auto size = (size_t)arg3;
		return context.handle_sysbpf(cmd, attr, size);
	} else if (sysno == __NR_perf_event_open) {
		spdlog::debug("SYS_PERF_EVENT_OPEN {} {} {} {} {} {}", arg1,
			      arg2, arg3, arg4, arg5, arg6);
		return context.handle_perfevent(
			(perf_event_attr *)(uintptr_t)arg1, (pid_t)arg2,
			(int)arg3, (int)arg4, (unsigned long)arg5);
	} else if (sysno == __NR_ioctl) {
		spdlog::debug("SYS_IOCTL {} {} {} {} {} {}", arg1, arg2, arg3,
			      arg4, arg5, arg6);
	}
	return context.orig_syscall_fn(sysno, arg1, arg2, arg3, arg4, arg5,
				       arg6);
}

int syscall_context::handle_close(int fd)
{
	bpftime_close(fd);
	return orig_close_fn(fd);
}

long syscall_context::handle_sysbpf(int cmd, union bpf_attr *attr, size_t size)
{
	start_up();
	errno = 0;
	char *errmsg;
	switch (cmd) {
	case BPF_MAP_CREATE: {
		spdlog::debug("Creating map");
		int id = bpftime_maps_create(
			attr->map_name, bpftime::bpf_map_attr{
						(int)attr->map_type,
						attr->key_size,
						attr->value_size,
						attr->max_entries,
						attr->map_flags,
						attr->map_ifindex,
						attr->btf_vmlinux_value_type_id,
						attr->btf_id,
						attr->btf_key_type_id,
						attr->btf_value_type_id,
						attr->map_extra,
					});
		spdlog::debug(
			"Created map {}, type={}, name={}, key_size={}, value_size={}",
			id, attr->map_type, attr->map_name, attr->key_size,
			attr->value_size);
		return id;
	}
	case BPF_MAP_LOOKUP_ELEM: {
		spdlog::debug("Looking up map {}");
		// Note that bpftime_map_lookup_elem is adapted as a bpf helper,
		// meaning that it will *return* the address of the matched
		// value. But here the syscall has a different interface. Here
		// we should write the bytes of the matched value to the pointer
		// that user gave us. So here needs a memcpy to achive such
		// thing.
		auto value_ptr = bpftime_map_lookup_elem(
			attr->map_fd, (const void *)(uintptr_t)attr->key);
		memcpy((void *)(uintptr_t)attr->value, value_ptr,
		       bpftime_map_value_size(attr->map_fd));
		return 0;
	}
	case BPF_MAP_UPDATE_ELEM: {
		spdlog::debug("Updating map");
		return bpftime_map_update_elem(
			attr->map_fd, (const void *)(uintptr_t)attr->key,
			(const void *)(uintptr_t)attr->value,
			(uint64_t)attr->flags);
	}
	case BPF_MAP_DELETE_ELEM: {
		spdlog::debug("Deleting map");
		return bpftime_map_delete_elem(
			attr->map_fd, (const void *)(uintptr_t)attr->key);
	}
	case BPF_MAP_GET_NEXT_KEY: {
		spdlog::debug("Getting next key");
		return (long)(uintptr_t)bpftime_map_get_next_key(
			attr->map_fd, (const void *)(uintptr_t)attr->key,
			(void *)(uintptr_t)attr->next_key);
	}
	case BPF_PROG_LOAD:
		// Load a program?
		{
			spdlog::debug(
				"Loading program `{}` license `{}` prog_type `{}` attach_type {} map_type {}",
				attr->prog_name,
				(const char *)(uintptr_t)attr->license,
				attr->prog_type, attr->attach_type,
				attr->map_type);

			// tracepoint -> BPF_PROG_TYPE_TRACEPOINT
			// uprobe/uretprobe -> BPF_PROG_TYPE_SOCKET_FILTER
			std::optional<std::string> simple_section_name;
			if (attr->prog_type == BPF_PROG_TYPE_TRACEPOINT) {
				simple_section_name = "tracepoint";
			} else if (attr->prog_type ==
				   BPF_PROG_TYPE_SOCKET_FILTER) {
				simple_section_name = "uprobe";
			}
#ifdef ENABLE_BPFTIME_VERIFIER
			// Only do verification for tracepoint/uprobe/uretprobe
			if (simple_section_name.has_value()) {
				spdlog::debug("Verying program {}",
					      attr->prog_name);
				auto result = verifier::verify_ebpf_program(
					(uint64_t *)(uintptr_t)attr->insns,
					(size_t)attr->insn_cnt,
					simple_section_name.value());
				if (result.has_value()) {
					std::ostringstream message;
					message << *result;
					// Print the program by bytes
					for (size_t i = 0; i < attr->insn_cnt;
					     i++) {
						uint64_t inst =
							((uint64_t *)(uintptr_t)
								 attr->insns)[i];
						message << std::setw(3)
							<< std::setfill('0')
							<< i << ": ";
						for (int j = 0; j < 8; j++) {
							message << std::hex
								<< std::uppercase
								<< std::setw(2)
								<< std::setfill(
									   '0')
								<< (inst & 0xff)
								<< " ";
							inst >>= 8;
						}
						message << std::endl;
					}
					spdlog::error(
						"Failed to verify program: {}",
						message.str());
					errno = EINVAL;
					return -1;
				}
			}
#endif
			int id = bpftime_progs_create(
				(ebpf_inst *)(uintptr_t)attr->insns,
				(size_t)attr->insn_cnt, attr->prog_name,
				attr->prog_type);
			spdlog::debug("Loaded program `{}` id={}",
				      attr->prog_name, id);
			return id;
		}
	case BPF_LINK_CREATE: {
		auto prog_fd = attr->link_create.prog_fd;
		auto target_fd = attr->link_create.target_fd;
		spdlog::debug("Creating link {} -> {}", prog_fd, target_fd);
		int id = bpftime_link_create(prog_fd, target_fd);
		spdlog::debug("Created link {}", id);
		return id;
	}
	case BPF_MAP_FREEZE: {
		// std::cout << "Freezing map" << std::endl;
		// if (auto itr = objs.find(attr->map_fd); itr != objs.end()) {
		// 	if (std::holds_alternative<EbpfMapWrapper>(
		// 		    *itr->second)) {
		// 		auto &map =
		// 			std::get<EbpfMapWrapper>(*itr->second);
		// 		map.frozen = true;
		// 		return 0;
		// 	} else {
		// 		errno = EINVAL;
		// 		return -1;
		// 	}
		// } else {
		// 	errno = ENOENT;
		// 	return -1;
		// }
		// errno = EINVAL;
		return 0;
	}
	case BPF_OBJ_GET_INFO_BY_FD: {
		spdlog::debug("Getting info by fd");
		bpftime::bpf_map_attr map_attr;
		const char *map_name;
		int map_type;
		int res = bpftime_map_get_info(attr->info.bpf_fd, &map_attr,
					       &map_name, &map_type);
		if (res < 0) {
			errno = res;
			return -1;
		}
		auto ptr = (bpf_map_info *)((uintptr_t)attr->info.info);
		ptr->btf_id = map_attr.btf_id;
		ptr->btf_key_type_id = map_attr.btf_key_type_id;
		ptr->btf_value_type_id = map_attr.btf_value_type_id;
		ptr->type = map_type;
		ptr->value_size = map_attr.value_size;
		ptr->btf_vmlinux_value_type_id =
			map_attr.btf_vmlinux_value_type_id;
		ptr->key_size = map_attr.key_size;
		ptr->id = attr->info.bpf_fd;
		ptr->ifindex = map_attr.ifindex;
		ptr->map_extra = map_attr.map_extra;
		// 		ptr->netns_dev = map.netns_dev;
		// 		ptr->netns_ino = map.netns_ino;
		ptr->max_entries = map_attr.max_ents;
		ptr->map_flags = map_attr.flags;
		strncpy(ptr->name, map_name, sizeof(ptr->name) - 1);
		return 0;
	}
	default:
		return orig_syscall_fn(__NR_bpf, (long)cmd,
				       (long)(uintptr_t)attr, (long)size);
	};
	return 0;
}

int syscall_context::handle_perfevent(perf_event_attr *attr, pid_t pid, int cpu,
				      int group_fd, unsigned long flags)
{
	if ((int)attr->type == determine_uprobe_perf_type()) {
		// NO legacy bpf types
		bool retprobe = attr->config & determine_uprobe_retprobe_bit();
		size_t ref_ctr_off =
			attr->config >> PERF_UPROBE_REF_CTR_OFFSET_SHIFT;
		const char *name = (const char *)(uintptr_t)attr->config1;
		uint64_t offset = attr->config2;
		spdlog::debug(
			"Creating uprobe name {} offset {} retprove {} ref_ctr_off {}",
			name, offset, retprobe, ref_ctr_off);
		int id = bpftime_uprobe_create(pid, name, offset, retprobe,
					       ref_ctr_off);
		// std::cout << "Created uprobe " << id << std::endl;
		spdlog::debug("Created uprobe {}", id);
		return id;
	} else if ((int)attr->type ==
		   (int)bpf_perf_event_handler::bpf_event_type::
			   PERF_TYPE_TRACEPOINT) {
		spdlog::debug("Detected tracepoint perf event creation");
		int fd = bpftime_tracepoint_create(pid, (int32_t)attr->config);
		spdlog::debug("Created tracepoint perf event with fd {}", fd);
		return fd;
	}

	return orig_syscall_fn(__NR_perf_event_open, (uint64_t)(uintptr_t)attr,
			       (uint64_t)pid, (uint64_t)cpu, (uint64_t)group_fd,
			       (uint64_t)flags);
}

void *syscall_context::handle_mmap64(void *addr, size_t length, int prot,
				     int flags, int fd, off64_t offset)
{
	spdlog::debug("Calling mocked mmap64");
	if (fd != -1 && bpftime_is_ringbuf_map(fd)) {
		spdlog::debug("Entering mmap64 handling for ringbuf fd: {}",
			      fd);
		if (prot == (PROT_WRITE | PROT_READ)) {
			if (auto ptr = bpftime_get_ringbuf_consumer_page(fd);
			    ptr != nullptr) {
				spdlog::debug(
					"Mapping consumer page {} to ringbuf fd {}",
					ptr, fd);

				return ptr;
			}
		} else if (prot == (PROT_READ)) {
			if (auto ptr = bpftime_get_ringbuf_producer_page(fd);
			    ptr != nullptr) {
				spdlog::debug(
					"Mapping producer page {} to ringbuf fd {}",
					ptr, fd);

				return ptr;
			}
		}
	} else if (fd != -1 && bpftime_is_array_map(fd)) {
		spdlog::debug("Entering mmap64 which handled array map");
		if (auto val = bpftime_get_array_map_raw_data(fd);
		    val != nullptr) {
			return val;
		}
	}

	auto ptr = orig_mmap64_fn(addr, length, prot | PROT_WRITE,
				  flags | MAP_ANONYMOUS, -1, 0);
	spdlog::debug(
		"Calling original mmap64: addr={}, length={}, prot={}, flags={}, fd={}, offset={}",
		addr, length, prot, flags, fd, offset);
	return orig_mmap64_fn(addr, length, prot, flags, fd, offset);
}

int syscall_context::handle_ioctl(int fd, unsigned long req, int data)
{
	int res;
	switch (req) {
	case PERF_EVENT_IOC_ENABLE: {
		spdlog::debug("Enabling perf event {}", fd);
		res = bpftime_attach_enable(fd);
		if (res < 0) {
			return orig_ioctl_fn(fd, req, data);
		}
		return res;
	}
	case PERF_EVENT_IOC_SET_BPF: {
		spdlog::debug("Setting bpf for perf event {} and bpf {}", fd,
			      data);
		res = bpftime_attach_perf_to_bpf(fd, data);
		if (res < 0) {
			return orig_ioctl_fn(fd, req, data);
		}
		return res;
	}
	default:
		return orig_ioctl_fn(fd, req, data);
	}
	return 0;
}

int syscall_context::handle_epoll_create1(int flags)
{
	return bpftime_epoll_create();
}

int syscall_context::handle_epoll_ctl(int epfd, int op, int fd,
				      epoll_event *evt)
{
	if (op == EPOLL_CTL_ADD) {
		int err = bpftime_add_ringbuf_fd_to_epoll(fd, epfd);
		if (err != 0) {
			spdlog::debug(
				"Failed to call mocked epoll_ctl: {}, calling original one..",
				err);
			return orig_epoll_ctl_fn(epfd, op, fd, evt);
		} else {
			return err;
		}
	} else {
		return orig_epoll_ctl_fn(epfd, op, fd, evt);
	}
}

int syscall_context::handle_epoll_wait(int epfd, epoll_event *evt,
				       int maxevents, int timeout)
{
	if (bpftime_is_epoll_handler(epfd)) {
		std::vector<int> fd_buf(maxevents);
		int ret = bpftime_ringbuf_poll(epfd, &fd_buf[0], maxevents,
					       timeout);
		if (ret >= 0) {
			for (size_t i = 0; i < (size_t)ret; i++) {
				evt[i] = epoll_event{
					.events = EPOLLIN,
					.data = { .fd = fd_buf[i] }
				};
			}
			return ret;
		}
	}
	return orig_epoll_wait_fn(epfd, evt, maxevents, timeout);
}