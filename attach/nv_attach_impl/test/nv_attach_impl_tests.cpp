#include "catch2/catch_test_macros.hpp"
#include "nv_attach_impl.hpp"
#include <iostream>
#include <ostream>

using namespace bpftime;
using namespace attach;

static const char *ORIGINAL_TEXT = R"(//
// Generated by LLVM NVPTX Back-End
//

.version 5.0
.target sm_60
.address_size 64

	// .globl	bpf_main
.extern .func  (.param .b64 func_retval0) _bpf_helper_ext_0001
(
	.param .b64 _bpf_helper_ext_0001_param_0,
	.param .b64 _bpf_helper_ext_0001_param_1,
	.param .b64 _bpf_helper_ext_0001_param_2,
	.param .b64 _bpf_helper_ext_0001_param_3,
	.param .b64 _bpf_helper_ext_0001_param_4
)
;

.visible .func bpf_main(
	.param .b64 bpf_main_param_0,
	.param .b64 bpf_main_param_1
)
{
	.local .align 8 .b8 	__local_depot0[16464];
	.reg .b64 	%SP;
	.reg .b64 	%SPL;
	.reg .b32 	%r<4>;
	.reg .b64 	%rd<7>;

	mov.u64 	%SPL, __local_depot0;
	cvta.local.u64 	%SP, %SPL;
	ld.param.u64 	%rd1, [bpf_main_param_0];
	add.u64 	%rd2, %SP, 0;
	add.u64 	%rd3, %SPL, 0;
	mov.b32 	%r1, 0;
	st.local.v2.u32 	[%rd3+16376], {%r1, %r1};
	mov.b32 	%r2, 111;
	st.local.v2.u32 	[%rd3+16368], {%r2, %r1};
	add.s64 	%rd4, %rd2, 16368;
	{ // callseq 0, 0
	.param .b64 param0;
	st.param.b64 	[param0], 4294967296;
	.param .b64 param1;
	st.param.b64 	[param1], %rd4;
	.param .b64 param2;
	.param .b64 param3;
	.param .b64 param4;
	.param .b64 retval0;
	call.uni (retval0), 
	_bpf_helper_ext_0001, 
	(
	param0, 
	param1, 
	param2, 
	param3, 
	param4
	);
	ld.param.b64 	%rd5, [retval0];
	} // callseq 0
	ld.u32 	%r3, [%rd5];
	st.u32 	[%rd1], %r3;
	ret;

}
)";

TEST_CASE("Test string replace")
{
	auto replaced = bpftime::attach::filter_compiled_ptx_for_ebpf_program(
		ORIGINAL_TEXT, "test_func");
	std::cout << "filtered " << std::endl << replaced << std::endl;
	REQUIRE(false);
}
