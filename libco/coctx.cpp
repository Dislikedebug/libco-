/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "coctx.h"
#include <string.h>


#define ESP 0
#define EIP 1
#define EAX 2
#define ECX 3
// -----------
#define RSP 0
#define RIP 1
#define RBX 2
#define RDI 3
#define RSI 4

#define RBP 5
#define R12 6
#define R13 7
#define R14 8
#define R15 9
#define RDX 10
#define RCX 11
#define R8 12
#define R9 13


//----- --------
// 32 bit
// | regs[0]: ret |
// | regs[1]: ebx |
// | regs[2]: ecx |
// | regs[3]: edx |
// | regs[4]: edi |
// | regs[5]: esi |
// | regs[6]: ebp |
// | regs[7]: eax |  = esp
enum
{
	kEIP = 0,
	kESP = 7,
};

//-------------
// 64 bit
//low | regs[0]: r15 |
//    | regs[1]: r14 |
//    | regs[2]: r13 |
//    | regs[3]: r12 |
//    | regs[4]: r9  |
//    | regs[5]: r8  | 
//    | regs[6]: rbp |
//    | regs[7]: rdi |
//    | regs[8]: rsi |
//    | regs[9]: ret |  //ret func addr
//    | regs[10]: rdx |
//    | regs[11]: rcx | 
//    | regs[12]: rbx |
//hig | regs[13]: rsp |
enum
{
	kRDI = 7,
	kRSI = 8,
	kRETAddr = 9,
	kRSP = 13,
};

//64 bit
extern "C"
{
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};
#if defined(__i386__)//对于32系统
int coctx_init( coctx_t *ctx )
{
	memset( ctx,0,sizeof(*ctx));
	return 0;
}
/*
params ctx  首次运行的协程用来上下文的地方
params  pfn  协程的工作函数
params  s   协程控制块
*/
//首次调用时，需要初始化regs
int coctx_make( coctx_t *ctx,coctx_pfn_t pfn,const void *s,const void *s1 )
{
	//make room for coctx_param
	char *sp = ctx->ss_sp + ctx->ss_size - sizeof(coctx_param_t);
	sp = (char*)((unsigned long)sp & -16L);

	//
	coctx_param_t* param = (coctx_param_t*)sp ;
	//
	param->s1 = s;
	param->s2 = s1;

	//对regs清0
	memset(ctx->regs, 0, sizeof(ctx->regs));

	//regs[7]存的是栈顶指针
	ctx->regs[ kESP ] = (char*)(sp) - sizeof(void*);
	//regs[0]存的是返回地址，这里被初始化为协程运行函数的函数指针
	ctx->regs[ kEIP ] = (char*)pfn;

	return 0;
}
#elif defined(__x86_64__)
//同理，但是对于64位系统，regs[13]保存栈顶指针，regs[9]保存返回地址
int coctx_make( coctx_t *ctx,coctx_pfn_t pfn,const void *s,const void *s1 )
{
	char *sp = ctx->ss_sp + ctx->ss_size;
	sp = (char*) ((unsigned long)sp & -16LL  );//含义为将二进制的最后四位都置为0，例如：sp= 33时，则结果为32；

	memset(ctx->regs, 0, sizeof(ctx->regs));

	ctx->regs[ kRSP ] = sp - 8;

	ctx->regs[ kRETAddr] = (char*)pfn;

	ctx->regs[ kRDI ] = (char*)s;
	ctx->regs[ kRSI ] = (char*)s1;
	return 0;
}

int coctx_init( coctx_t *ctx )
{
	//将ctx清0
	memset( ctx,0,sizeof(*ctx));
	return 0;
}

#endif

