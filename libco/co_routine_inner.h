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


#ifndef __CO_ROUTINE_INNER_H__

#include "co_routine.h"
#include "coctx.h"
struct stCoRoutineEnv_t;
struct stCoSpec_t
{
	void *value;
};


//一个共享栈
struct stStackMem_t
{
	stCoRoutine_t* ocupy_co;//当前正在使用该共享栈的协程
	int stack_size;//栈大小
	char* stack_bp; //stack_buffer + stack_size  栈底
	char* stack_buffer;//栈顶

};
//共享栈，是一个数组，数组每个元素是个共享栈
struct stShareStack_t
{
	unsigned int alloc_idx; //目前正在使用的贡献栈id
	int stack_size;//共享栈的大小
	int count;//共享栈数量
	stStackMem_t** stack_array;//数组
};


//协程控制块
struct stCoRoutine_t
{
	//协程执行环境，一个线程所有的协程共享env
	stCoRoutineEnv_t *env;
	//协程执行函数
	pfn_co_routine_t pfn;
	void *arg;

	//保存协程上下文：寄存器和栈
	coctx_t ctx;

	//
	char cStart;  //是否开始运行
	char cEnd; //是否已经结束
	char cIsMain; //是否是main主协程
	char cEnableSysHook; //是否打开钩子机制
	char cIsShareStack; //是否采用共享栈

	void *pvEnv;

	//char sRunStack[ 1024 * 128 ];
	//栈  内存
	stStackMem_t* stack_mem;


	//save satck buffer while confilct on same stack_buffer;
	//如果采用共享栈模式， 需要共享栈的地址stack_sp  以及保存栈内容缓冲save_buffer
	char* stack_sp; 
	unsigned int save_size;
	char* save_buffer;

	//存放与协程绑定的数据
	stCoSpec_t aSpec[1024];

};



//1.env
void 				co_init_curr_thread_env();
stCoRoutineEnv_t *	co_get_curr_thread_env();

//2.coroutine
void    co_free( stCoRoutine_t * co );
void    co_yield_env(  stCoRoutineEnv_t *env );

//3.func



//-----------------------------------------------------------------------------------------------

struct stTimeout_t;
struct stTimeoutItem_t ;

stTimeout_t *AllocTimeout( int iSize );
void 	FreeTimeout( stTimeout_t *apTimeout );
int  	AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,uint64_t allNow );

struct stCoEpoll_t;
stCoEpoll_t * AllocEpoll();
void 		FreeEpoll( stCoEpoll_t *ctx );

stCoRoutine_t *		GetCurrThreadCo();
void 				SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev );

typedef void (*pfnCoRoutineFunc_t)();

#endif

#define __CO_ROUTINE_INNER_H__
