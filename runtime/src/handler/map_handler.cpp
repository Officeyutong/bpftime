/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2022, eunomia-bpf org
 * All rights reserved.
 */
#ifdef BPFTIME_ENABLE_CUDA_ATTACH
#include "bpf_map/gpu/nv_gpu_array_map.hpp"
#endif
#include "bpf_map/userspace/lru_var_hash_map.hpp"
#include "bpf_map/userspace/per_cpu_array_map.hpp"
#include "bpf_map/userspace/per_cpu_hash_map.hpp"
#include "bpf_map/userspace/stack_trace_map.hpp"
#include "bpftime_shm_internal.hpp"
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
#include "cuda.h"
#endif
#include <bpf_map/userspace/perf_event_array_map.hpp>
#include "spdlog/spdlog.h"
#include <cassert>
#include <handler/map_handler.hpp>
#include <bpf_map/userspace/array_map.hpp>
#include <bpf_map/userspace/fix_hash_map.hpp>
#include <bpf_map/userspace/var_hash_map.hpp>
#include <bpf_map/userspace/ringbuf_map.hpp>
#ifdef BPFTIME_BUILD_WITH_LIBBPF
#include <bpf_map/shared/array_map_kernel_user.hpp>
#include <bpf_map/shared/hash_map_kernel_user.hpp>
#include <bpf_map/shared/percpu_array_map_kernel_user.hpp>
#include <bpf_map/shared/perf_event_array_kernel_user.hpp>
#endif
#include <bpf_map/userspace/prog_array.hpp>
#include <bpf_map/userspace/map_in_maps.hpp>
#include <unistd.h>

using boost::interprocess::interprocess_sharable_mutex;
using boost::interprocess::scoped_lock;
using boost::interprocess::sharable_lock;

namespace bpftime
{

#ifdef BPFTIME_USE_VAR_HASH_MAP
using hash_map_impl = var_size_hash_map_impl;
#else
using hash_map_impl = fix_size_hash_map_impl;
#endif

bpftime_map_ops global_map_ops_table[(int)bpf_map_type::BPF_MAP_TYPE_MAX] = {
	{ 0 }
};

std::string bpf_map_handler::get_container_name()
{
	return "ebpf_map_fd_" + std::string(name.c_str());
}

uint32_t bpf_map_handler::get_value_size() const
{
	return value_size;
}

uint32_t bpf_map_handler::get_userspace_value_size() const
{
	auto result = value_size;
	if ((type == bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY) ||
	    (type == bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH)) {
		result *= sysconf(_SC_NPROCESSORS_ONLN);
	}
	if (type == bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP) {
		result *= this->attr.gpu_thread_count;
		SPDLOG_DEBUG(
			"Value size of BPF_MAP_TYPE_NV_GPU_ARRAY_MAP is {}",
			result);
	}
	return result;
}

std::optional<ringbuf_map_impl *>
bpf_map_handler::try_get_ringbuf_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_RINGBUF)
		return {};
	return static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
}

std::optional<array_map_impl *> bpf_map_handler::try_get_array_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_ARRAY)
		return {};
	return static_cast<array_map_impl *>(map_impl_ptr.get());
}

const void *bpf_map_handler::map_lookup_elem(const void *key,
					     bool from_syscall) const
{
	const auto do_lookup = [&](auto *impl) -> const void * {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_lookup(key);
		} else {
			return impl->elem_lookup(key);
		}
	};
	const auto do_lookup_userspace = [&](auto *impl) -> const void * {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_lookup_userspace(key);
		} else {
			return impl->elem_lookup_userspace(key);
		}
	};

	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return from_syscall ? do_lookup_userspace(impl) :
				      do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return from_syscall ? do_lookup_userspace(impl) :
				      do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_STACK_TRACE: {
		auto impl =
			static_cast<stack_trace_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
#ifdef BPFTIME_BUILD_WITH_LIBBPF
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_lookup(impl);
	}
#endif
	case bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS: {
		auto impl = static_cast<array_map_of_maps_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_LRU_HASH: {
		auto impl = static_cast<lru_var_hash_map_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	case bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP: {
		auto impl = static_cast<nv_gpu_array_map_impl *>(
			map_impl_ptr.get());
		return do_lookup(impl);
	}
#endif
	default:
		auto func_ptr = global_map_ops_table[(int)type].elem_lookup;
		if (func_ptr) {
			return func_ptr(id, key, from_syscall);
		} else {
			SPDLOG_ERROR("Unsupported map type: {}", (int)type);
			return nullptr;
		}
	}
	return 0;
}

long bpf_map_handler::map_update_elem(const void *key, const void *value,
				      uint64_t flags, bool from_syscall) const
{
	const auto do_update = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_update(key, value, flags);
		} else {
			return impl->elem_update(key, value, flags);
		}
	};

	const auto do_update_userspace = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_update_userspace(key, value, flags);
		} else {
			return impl->elem_update_userspace(key, value, flags);
		}
	};
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return from_syscall ? do_update_userspace(impl) :
				      do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return from_syscall ? do_update_userspace(impl) :
				      do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_STACK_TRACE: {
		auto impl =
			static_cast<stack_trace_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
#ifdef BPFTIME_BUILD_WITH_LIBBPF
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_update(impl);
	}
#endif
	case bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS: {
		if (!from_syscall) {
			// Map in maps only support update from syscall
			return -EINVAL;
		}
		auto impl = static_cast<array_map_of_maps_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_LRU_HASH: {
		auto impl = static_cast<lru_var_hash_map_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	case bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP: {
		auto impl = static_cast<nv_gpu_array_map_impl *>(
			map_impl_ptr.get());
		return do_update(impl);
	}
#endif
	default:
		auto func_ptr = global_map_ops_table[(int)type].elem_update;
		if (func_ptr) {
			return func_ptr(id, key, value, flags, from_syscall);
		} else {
			SPDLOG_ERROR("Unsupported map type: {}", (int)type);
			return -1;
		}
	}
	return 0;
}

int bpf_map_handler::bpf_map_get_next_key(const void *key, void *next_key,
					  bool from_syscall) const
{
	const auto do_get_next_key = [&](auto *impl) -> int {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->map_get_next_key(key, next_key);
		} else {
			return impl->map_get_next_key(key, next_key);
		}
	};
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_STACK_TRACE: {
		auto impl =
			static_cast<stack_trace_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
#if __linux__ && defined(BPFTIME_BUILD_WITH_LIBBPF)
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_get_next_key(impl);
	}
#endif
	case bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS: {
		auto impl = static_cast<array_map_of_maps_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_LRU_HASH: {
		auto impl = static_cast<lru_var_hash_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	case bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP: {
		auto impl = static_cast<nv_gpu_array_map_impl *>(
			map_impl_ptr.get());
		return do_get_next_key(impl);
	}
#endif
	default:
		auto func_ptr =
			global_map_ops_table[(int)type].map_get_next_key;
		if (func_ptr) {
			return func_ptr(id, key, next_key, from_syscall);
		} else {
			SPDLOG_ERROR("Unsupported map type: {}", (int)type);
			return -1;
		}
	}
	return 0;
}

long bpf_map_handler::map_delete_elem(const void *key, bool from_syscall) const
{
	const auto do_delete = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_delete(key);
		} else {
			return impl->elem_delete(key);
		}
	};
	const auto do_delete_userspace = [&](auto *impl) -> long {
		if (impl->should_lock) {
			bpftime_lock_guard guard(map_lock);
			return impl->elem_delete_userspace(key);
		} else {
			return impl->elem_delete_userspace(key);
		}
	};

	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		auto impl = static_cast<hash_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		auto impl = static_cast<array_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto impl = static_cast<ringbuf_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_map_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		auto impl = static_cast<per_cpu_array_map_impl *>(
			map_impl_ptr.get());
		return from_syscall ? do_delete_userspace(impl) :
				      do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		auto impl = static_cast<per_cpu_hash_map_impl *>(
			map_impl_ptr.get());
		return from_syscall ? do_delete_userspace(impl) :
				      do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_STACK_TRACE: {
		auto impl =
			static_cast<stack_trace_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
#ifdef BPFTIME_BUILD_WITH_LIBBPF
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		auto impl = static_cast<array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		auto impl = static_cast<hash_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		auto impl = static_cast<percpu_array_map_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		auto impl = static_cast<perf_event_array_kernel_user_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		auto impl =
			static_cast<prog_array_map_impl *>(map_impl_ptr.get());
		return do_delete(impl);
	}
#endif
	case bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS: {
		if (!from_syscall) {
			// Map in maps only support update from syscall
			return -EINVAL;
		}
		auto impl = static_cast<array_map_of_maps_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
	case bpf_map_type::BPF_MAP_TYPE_LRU_HASH: {
		auto impl = static_cast<lru_var_hash_map_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	case bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP: {
		auto impl = static_cast<nv_gpu_array_map_impl *>(
			map_impl_ptr.get());
		return do_delete(impl);
	}
#endif
	default:
		auto func_ptr = global_map_ops_table[(int)type].elem_delete;
		if (func_ptr) {
			return func_ptr(id, key, from_syscall);
		} else {
			SPDLOG_ERROR("Unsupported map type: {}", (int)type);
			return -1;
		}
	}
	return 0;
}

int bpf_map_handler::map_init(managed_shared_memory &memory)
{
	auto container_name = get_container_name();
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH: {
		map_impl_ptr =
			memory.construct<hash_map_impl>(container_name.c_str())(
				memory, max_entries, key_size, value_size);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_ARRAY: {
		map_impl_ptr = memory.construct<array_map_impl>(
			container_name.c_str())(memory, value_size,
						max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF: {
		auto max_ent = max_entries;
		int pop_cnt = 0;
		while (max_ent) {
			pop_cnt += (max_ent & 1);
			max_ent >>= 1;
		}
		if (pop_cnt != 1) {
			SPDLOG_ERROR(
				"Failed to create ringbuf map, max_entries must be a power of 2, current: {}",
				max_entries);
			return -1;
		}
		map_impl_ptr = memory.construct<ringbuf_map_impl>(
			container_name.c_str())(max_entries, memory);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY: {
		map_impl_ptr = memory.construct<perf_event_array_map_impl>(
			container_name.c_str())(memory, key_size, value_size,
						max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY: {
		map_impl_ptr = memory.construct<per_cpu_array_map_impl>(
			container_name.c_str())(memory, value_size,
						max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH: {
		map_impl_ptr = memory.construct<per_cpu_hash_map_impl>(
			container_name.c_str())(memory, key_size, value_size,
						max_entries);
		return 0;
	}
#ifdef BPFTIME_BUILD_WITH_LIBBPF
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY: {
		map_impl_ptr = memory.construct<array_map_kernel_user_impl>(
			container_name.c_str())(memory, attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH: {
		map_impl_ptr = memory.construct<hash_map_kernel_user_impl>(
			container_name.c_str())(memory, attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY: {
		map_impl_ptr =
			memory.construct<percpu_array_map_kernel_user_impl>(
				container_name.c_str())(memory,
							attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY: {
		map_impl_ptr =
			memory.construct<perf_event_array_kernel_user_impl>(
				container_name.c_str())(
				memory, 4, 4, sysconf(_SC_NPROCESSORS_ONLN),
				attr.kernel_bpf_map_id);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY: {
		map_impl_ptr = memory.construct<prog_array_map_impl>(
			container_name.c_str())(memory, key_size, value_size,
						max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_STACK_TRACE: {
		map_impl_ptr = memory.construct<stack_trace_map_impl>(
			container_name.c_str())(memory, key_size, value_size,
						max_entries);
		return 0;
	}
#endif
	case bpf_map_type::BPF_MAP_TYPE_ARRAY_OF_MAPS: {
		map_impl_ptr = memory.construct<array_map_of_maps_impl>(
			container_name.c_str())(memory, max_entries);
		return 0;
	}
	case bpf_map_type::BPF_MAP_TYPE_LRU_HASH: {
		map_impl_ptr = memory.construct<lru_var_hash_map_impl>(
			container_name.c_str())(memory, key_size, value_size,
						max_entries);
		return 0;
	}

	// TODO: Move these CUDA sentences to a more appropriate position
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
		static CUcontext context;
		static CUdevice device;
	case bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP: {
		auto total_buffer_size = (uint64_t)value_size * max_entries *
					 attr.gpu_thread_count;
		CUdeviceptr ptr;
		SPDLOG_INFO(
			"Initializing map type of BPF_MAP_TYPE_NV_GPU_ARRAY_MAP, total_buffer_size={}",
			total_buffer_size);

		shm_holder.global_shared_memory.set_enable_mock(false);
		if (!device) {
			cuDeviceGet(&device, 0);
			cuCtxCreate(&context, 0, device);
			SPDLOG_INFO(
				"CUDA context for thread {} has been set to {:x}",
				gettid(), (uintptr_t)context);
		}

		if (auto err = cuMemAlloc(&ptr, total_buffer_size);
		    err != CUDA_SUCCESS) {
			SPDLOG_ERROR(
				"Unable to allocate GPU buffer for nv_gpu_array_map_impl: {}",
				(int)err);
			return -1;
		}
		if (auto err = cuMemsetD8(ptr, 0, total_buffer_size);
		    err != CUDA_SUCCESS) {
			SPDLOG_ERROR("Unable to fill GPU buffer with zero: {}",
				     (int)err);
		}
		CUipcMemHandle handle;
		if (auto err = cuIpcGetMemHandle(&handle, ptr);
		    err != CUDA_SUCCESS) {
			SPDLOG_ERROR(
				"Unable to open CUDA IPC handle for nv_gpu_array_map_impl: {}",
				(int)err);
			return -1;
		}

		shm_holder.global_shared_memory.set_enable_mock(true);
		SPDLOG_INFO(
			"Map {} (nv_gpu_array_map_impl) has space for thread count {}",
			container_name.c_str(), attr.gpu_thread_count);
		map_impl_ptr = memory.construct<nv_gpu_array_map_impl>(
			container_name.c_str())(memory, handle, ptr, value_size,
						max_entries,
						attr.gpu_thread_count);
		return 0;
	}
#endif
	default:
		if (bpftime_get_agent_config().allow_non_buildin_map_types) {
			SPDLOG_INFO("non-builtin map type: {}", (int)type);
			map_impl_ptr = nullptr;
			auto func_ptr =
				global_map_ops_table[(int)type].alloc_map;
			if (func_ptr) {
				return func_ptr(id, name.c_str(), attr);
			}
			return 0;
		} else {
			SPDLOG_ERROR("Unsupported map type: {}", (int)type);
			return -1;
		}
	}
	return 0;
}

void bpf_map_handler::map_free(managed_shared_memory &memory)
{
	auto container_name = get_container_name();
	switch (type) {
	case bpf_map_type::BPF_MAP_TYPE_HASH:
		memory.destroy<hash_map_impl>(container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_ARRAY:
		memory.destroy<array_map_impl>(container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_RINGBUF:
		memory.destroy<ringbuf_map_impl>(container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY:
		memory.destroy<perf_event_array_map_impl>(
			container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY:
		memory.destroy<per_cpu_array_map_impl>(container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH:
		memory.destroy<per_cpu_hash_map_impl>(container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_STACK_TRACE:
		memory.destroy<stack_trace_map_impl>(container_name.c_str());
		break;
#ifdef BPFTIME_BUILD_WITH_LIBBPF
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_ARRAY:
		memory.destroy<array_map_kernel_user_impl>(
			container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_HASH:
		memory.destroy<hash_map_kernel_user_impl>(
			container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERCPU_ARRAY:
		memory.destroy<percpu_array_map_kernel_user_impl>(
			container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY:
		memory.destroy<perf_event_array_kernel_user_impl>(
			container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY:
		memory.destroy<prog_array_map_impl>(container_name.c_str());
		break;
	case bpf_map_type::BPF_MAP_TYPE_LRU_HASH:
		memory.destroy<lru_var_hash_map_impl>(container_name.c_str());
		break;
#endif
#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	case bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP:
		memory.destroy<nv_gpu_array_map_impl>(container_name.c_str());
		break;
#endif
	default:
		auto func_ptr = global_map_ops_table[(int)type].map_free;
		if (func_ptr) {
			func_ptr(id);
		} else {
			SPDLOG_ERROR("Unsupported map type: {}", (int)type);
		}
	}
	map_impl_ptr = nullptr;
	return;
}
std::optional<stack_trace_map_impl *>
bpf_map_handler::try_get_stack_trace_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_STACK_TRACE)
		return {};
	return static_cast<stack_trace_map_impl *>(map_impl_ptr.get());
}
std::optional<perf_event_array_kernel_user_impl *>
bpf_map_handler::try_get_shared_perf_event_array_map_impl() const
{
	if (type != bpf_map_type::BPF_MAP_TYPE_KERNEL_USER_PERF_EVENT_ARRAY)
		return {};
	return static_cast<perf_event_array_kernel_user_impl *>(
		map_impl_ptr.get());
}
uint64_t bpf_map_handler::get_gpu_map_max_thread_count() const
{
#if !defined(BPFTIME_ENABLE_CUDA_ATTACH) && !defined(BPFTIME_ENABLE_ROCM_ATTACH)
	return 0;
#endif

#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	if (this->type == bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP) {
		return static_cast<nv_gpu_array_map_impl *>(map_impl_ptr.get())
			->get_max_thread_count();
	}

#endif

	SPDLOG_DEBUG("Not a GPU map!");
	return 0;
}
void *bpf_map_handler::get_gpu_map_extra_buffer() const
{
#if !defined(BPFTIME_ENABLE_CUDA_ATTACH) && !defined(BPFTIME_ENABLE_ROCM_ATTACH)
	return nullptr;
#endif

#if defined(BPFTIME_ENABLE_CUDA_ATTACH)
	if (this->type == bpf_map_type::BPF_MAP_TYPE_NV_GPU_ARRAY_MAP) {
		return (void *)static_cast<nv_gpu_array_map_impl *>(
			       map_impl_ptr.get())
			->get_gpu_mem_buffer();
	}

#endif

	SPDLOG_ERROR("Not a GPU map!");
	return nullptr;
}
int bpftime_register_map_ops(int map_type, bpftime_map_ops *ops)
{
	if (map_type < 0 || map_type >= (int)bpf_map_type::BPF_MAP_TYPE_MAX) {
		SPDLOG_ERROR("Invalid map type: {}", map_type);
		return -1;
	}
	global_map_ops_table[map_type] = *ops;
	return 0;
}

} // namespace bpftime
