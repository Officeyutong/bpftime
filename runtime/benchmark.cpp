#include <attach/attach_manager/frida_attach_manager.hpp>
#include <cstdint>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <ios>
#include <iostream>
#include <ostream>
using namespace bpftime;

const size_t TEST_TIME = 1e8;

extern "C" __attribute__((optnone)) uint64_t uprobe_test_func(uint64_t a,
							      uint64_t b)
{
	return a + b;
}
inline double run_test()
{
	auto start = std::chrono::high_resolution_clock::now();
	for (size_t i = 1; i <= TEST_TIME; i++) {
		uprobe_test_func(i, i + 1);
	}
	auto end = std::chrono::high_resolution_clock::now();
	auto diff = std::chrono::duration_cast<std::chrono::nanoseconds>(end -
									 start);
	std::cout << "Time usage: " << std::fixed << std::setprecision(9)
		  << ((double)diff.count() / TEST_TIME) << std::endl;
	return ((double)diff.count() / TEST_TIME);
}
int main(int argc, const char **argv)
{
	bpftime::frida_attach_manager man;
	uint64_t call_time = 0;

	if (argc == 2 && strcmp(argv[1], "uprobe") == 0) {
		std::cout << "Running uprobe" << std::endl;
		man.attach_uprobe_at((void *)uprobe_test_func,
				     [&](const auto &regs) { call_time++; });
		run_test();
	} else if (argc == 2 && strcmp(argv[1], "none") == 0) {
		run_test();
	} else {
		std::cout << "Running override" << std::endl;
		man.attach_uprobe_override_at((void *)uprobe_test_func,
					      [&](const auto &regs) {
						      call_time++;
					      });
		run_test();
	}

	return 0;
}
