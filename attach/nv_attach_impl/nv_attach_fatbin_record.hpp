#include "cuda.h"
#include <map>
#include <memory>
#include <string>
#include <vector>
namespace bpftime
{
namespace attach
{
struct fatbin_record {
	struct ptx_in_module {
		CUmodule module_ptr;
		ptx_in_module(CUmodule module_ptr) : module_ptr(module_ptr)
		{
		}
		virtual ~ptx_in_module();
	};
	struct variable_info {
		std::string symbol_name;
		CUdeviceptr ptr;
		size_t size;
		ptx_in_module *ptx;
	};

	struct kernel_info {
		std::string symbol_name;
		CUfunction func;
		ptx_in_module *ptx;
	};
	std::vector<std::unique_ptr<ptx_in_module>> ptxs;
	std::map<void *, variable_info> variable_addr_to_symbol;
	std::map<void *, kernel_info> function_addr_to_symbol;
	void **fatbin_handle = nullptr;
	virtual ~fatbin_record();
	bool find_and_fill_variable_info(void *ptr, const char *symbol_name);
	bool find_and_fill_function_info(void *ptr, const char *symbol_name);
};

} // namespace attach
} // namespace bpftime
