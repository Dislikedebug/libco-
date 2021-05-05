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

#include "co_routine.h"
#include "co_routine_inner.h"
#include "co_epoll.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>

#include <poll.h>
#include <sys/time.h>
#include <errno.h>

#include <assert.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C"
{
	////保存当前上下文到第一个参数，并激活第二个参数的上下文
	extern void coctx_swap( coctx_t *,coctx_t* ) asm("coctx_swap");
};

using namespace std;
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env );
struct stCoEpoll_t;

//协程运行的环境，一个线程所有协程都共享这个结构体
struct stCoRoutineEnv_t
{
	stCoRoutine_t *pCallStack[ 128 ];//协程调用栈，栈顶为当前运行协程的控制块
	int iCallStackSize;//栈大小
	stCoEpoll_t *pEpoll;//epoll描述符

	//for copy stack log lastco and nextco
	stCoRoutine_t* pending_co;
	stCoRoutine_t* ocupy_co;
};
//int socket(int domain, int type, int protocol);
void co_log_err( const char *fmt,... )
{
}


#if defined( __LIBCO_RDTSCP__) 
static unsigned long long counter(void)
{
	register uint32_t lo, hi;
	register unsigned long long o;
	__asm__ __volatile__ (
			"rdtscp" : "=a"(lo), "=d"(hi)
			);
	o = hi;
	o <<= 32;
	return (o | lo);

}
static unsigned long long getCpuKhz()
{
	FILE *fp = fopen("/proc/cpuinfo","r");
	if(!fp) return 1;
	char buf[4096] = {0};
	fread(buf,1,sizeof(buf),fp);
	fclose(fp);

	char *lp = strstr(buf,"cpu MHz");
	if(!lp) return 1;
	lp += strlen("cpu MHz");
	while(*lp == ' ' || *lp == '\t' || *lp == ':')
	{
		++lp;
	}

	double mhz = atof(lp);
	unsigned long long u = (unsigned long long)(mhz * 1000);
	return u;
}
#endif

//获取当前时间，以us为单位
static unsigned long long GetTickMS()
{
#if defined( __LIBCO_RDTSCP__) 
	static uint32_t khz = getCpuKhz();
	return counter() / khz;
#else
	struct timeval now = { 0 };
	gettimeofday( &now,NULL );
	unsigned long long u = now.tv_sec;
	u *= 1000;
	u += now.tv_usec / 1000;
	return u;
#endif
}

static pid_t GetPid()
{
    static __thread pid_t pid = 0;
    static __thread pid_t tid = 0;
    if( !pid || !tid || pid != getpid() )
    {
        pid = getpid();
#if defined( __APPLE__ )
		tid = syscall( SYS_gettid );
		if( -1 == (long)tid )
		{
			tid = pid;
		}
#else 
        tid = syscall( __NR_gettid );
#endif

    }
    return tid;

}
/*
static pid_t GetPid()
{
	char **p = (char**)pthread_self();
	return p ? *(pid_t*)(p + 18) : getpid();
}
*/
//将链表项ap,从链表中删除
template <class T,class TLink>
void RemoveFromLink(T *ap)
{
	TLink *lst = ap->pLink;
	if(!lst) return ;
	assert( lst->head && lst->tail );

	if( ap == lst->head )
	{
		lst->head = ap->pNext;
		if(lst->head)
		{
			lst->head->pPrev = NULL;
		}
	}
	else
	{
		if(ap->pPrev)
		{
			ap->pPrev->pNext = ap->pNext;
		}
	}

	if( ap == lst->tail )
	{
		lst->tail = ap->pPrev;
		if(lst->tail)
		{
			lst->tail->pNext = NULL;
		}
	}
	else
	{
		ap->pNext->pPrev = ap->pPrev;
	}

	ap->pPrev = ap->pNext = NULL;
	ap->pLink = NULL;
}

//将链表项添加到链表末尾
template <class TNode,class TLink>
void inline AddTail(TLink*apLink,TNode *ap)
{
	if( ap->pLink )
	{
		return ;
	}
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)ap;
		ap->pNext = NULL;
		ap->pPrev = apLink->tail;
		apLink->tail = ap;
	}
	else
	{
		apLink->head = apLink->tail = ap;
		ap->pNext = ap->pPrev = NULL;
	}
	ap->pLink = apLink;
}

//从链表apLink头部取走一个链表项
template <class TNode,class TLink>
void inline PopHead( TLink*apLink )
{
	if( !apLink->head ) 
	{
		return ;
	}
	TNode *lp = apLink->head;
	if( apLink->head == apLink->tail )
	{
		apLink->head = apLink->tail = NULL;
	}
	else
	{
		apLink->head = apLink->head->pNext;
	}

	lp->pPrev = lp->pNext = NULL;
	lp->pLink = NULL;

	if( apLink->head )
	{
		apLink->head->pPrev = NULL;
	}
}

//将apOther槽下所有定时事件链表接到apLink链表前中
template <class TNode,class TLink>
void inline Join( TLink*apLink,TLink *apOther )
{
	//printf("apOther %p\n",apOther);
	if( !apOther->head )
	{
		return ;
	}
	TNode *lp = apOther->head;
	while( lp )
	{
		lp->pLink = apLink;
		lp = lp->pNext;
	}
	lp = apOther->head;
	if(apLink->tail)
	{
		apLink->tail->pNext = (TNode*)lp;
		lp->pPrev = apLink->tail;
		apLink->tail = apOther->tail;
	}
	else
	{
		apLink->head = apOther->head;
		apLink->tail = apOther->tail;
	}

	apOther->head = apOther->tail = NULL;
}

//分配一个栈内存
/////////////////for copy stack //////////////////////////
stStackMem_t* co_alloc_stackmem(unsigned int stack_size)
{
	stStackMem_t* stack_mem = (stStackMem_t*)malloc(sizeof(stStackMem_t));
	stack_mem->ocupy_co= NULL;
	stack_mem->stack_size = stack_size;
	stack_mem->stack_buffer = (char*)malloc(stack_size);
	stack_mem->stack_bp = stack_mem->stack_buffer + stack_size;
	return stack_mem;
}

//创建count个大小为stack_size的共享栈
stShareStack_t* co_alloc_sharestack(int count, int stack_size)
{
	stShareStack_t* share_stack = (stShareStack_t*)malloc(sizeof(stShareStack_t));
	share_stack->alloc_idx = 0;
	share_stack->stack_size = stack_size;

	//alloc stack array
	share_stack->count = count;
	stStackMem_t** stack_array = (stStackMem_t**)calloc(count, sizeof(stStackMem_t*));
	for (int i = 0; i < count; i++)
	{
		stack_array[i] = co_alloc_stackmem(stack_size);
	}
	share_stack->stack_array = stack_array;
	return share_stack;
}

//在共享栈，获取协程的栈内存
static stStackMem_t* co_get_stackmem(stShareStack_t* share_stack)
{
	if (!share_stack)
	{
		return NULL;
	}
	//轮询使用共享栈
	int idx = share_stack->alloc_idx % share_stack->count;
	share_stack->alloc_idx++;

	return share_stack->stack_array[idx];
}


// ----------------------------------------------------------------------------
//时间轮槽项结构
struct stTimeoutItemLink_t;
//链表项结构
struct stTimeoutItem_t;
//调度的核心epoll，一个线程所有协程共享
struct stCoEpoll_t
{
	int iEpollFd;//epoll描述符
	static const int _EPOLL_SIZE = 1024 * 10;//epoll最大返回就绪事件个数

	struct stTimeout_t *pTimeout;//时间轮定时器指针

	struct stTimeoutItemLink_t *pstTimeoutList;//超时事件链表

	struct stTimeoutItemLink_t *pstActiveList;//就绪事件链表

	co_epoll_res *result; //epoll_wait返回结果

};
//就绪事件预处理回调函数
typedef void (*OnPreparePfn_t)( stTimeoutItem_t *,struct epoll_event &ev, stTimeoutItemLink_t *active );
//就绪事件处理事件回调函数
typedef void (*OnProcessPfn_t)( stTimeoutItem_t *);

//时间轮槽中链表表项的结构
struct stTimeoutItem_t
{

	enum
	{
		eMaxTimeout = 40 * 1000 //40s
	};
	stTimeoutItem_t *pPrev;
	stTimeoutItem_t *pNext;
	stTimeoutItemLink_t *pLink;//指向槽

	unsigned long long ullExpireTime;//定时时间

	OnPreparePfn_t pfnPrepare;//预处理回调函数
	OnProcessPfn_t pfnProcess;//处理回调函数

	void *pArg; // 所关联的协程co
	bool bTimeout;//是否超时
};

//超时链表结构，时间轮槽都是一个超时链表
struct stTimeoutItemLink_t
{
	stTimeoutItem_t *head;
	stTimeoutItem_t *tail;

};

//负责超时事件的管理，时间轮
struct stTimeout_t
{
	//环状数组
	stTimeoutItemLink_t *pItems;
	//槽数量，每个槽代表1ms,一共60 000个槽，所以最多可以表达 1 min以内的超时事件
	int iItemSize;

	unsigned long long ullStart;//代表最近超时时间的时间戳
	long long llStartIdx;//对应index
};

//在堆中申请一个时间轮，默认为 60*1000个槽
stTimeout_t *AllocTimeout( int iSize )
{
	stTimeout_t *lp = (stTimeout_t*)calloc( 1,sizeof(stTimeout_t) );	

	lp->iItemSize = iSize;
	lp->pItems = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) * lp->iItemSize );

	lp->ullStart = GetTickMS();
	lp->llStartIdx = 0;

	return lp;
}
//释放时间轮
void FreeTimeout( stTimeout_t *apTimeout )
{
	free( apTimeout->pItems );
	free ( apTimeout );
}

//把一个定时事件apItem添加到时间轮中apTimeout
/*
@param apTimeout  -  时间轮
@param  apltem  待插入的超时事件
@param  allow  当前事件
*/
int AddTimeout( stTimeout_t *apTimeout,stTimeoutItem_t *apItem ,unsigned long long allNow )
{
	if( apTimeout->ullStart == 0 )
	{
		//设置时间轮最早超时时间为当前时间
		apTimeout->ullStart = allNow;
		//其对应idx设为0
		apTimeout->llStartIdx = 0;
	}
	//事件定时时间小于时间轮最近超时时间的时间戳
	if( allNow < apTimeout->ullStart )
	{
		co_log_err("CO_ERR: AddTimeout line %d allNow %llu apTimeout->ullStart %llu",
					__LINE__,allNow,apTimeout->ullStart);

		return __LINE__;
	}
	//事件定时时间小于当前时间
	if( apItem->ullExpireTime < allNow )
	{
		co_log_err("CO_ERR: AddTimeout line %d apItem->ullExpireTime %llu allNow %llu apTimeout->ullStart %llu",
					__LINE__,apItem->ullExpireTime,allNow,apTimeout->ullStart);

		return __LINE__;
	}
	//计算当前超时事件的触发时间距离时间轮中最近的超时时间的差
	int diff = apItem->ullExpireTime - apTimeout->ullStart;

	//时间差大于1分钟
	if( diff >= apTimeout->iItemSize )
	{
		co_log_err("CO_ERR: AddTimeout line %d diff %d",
					__LINE__,diff);

		return __LINE__;
	}
	//根据diff计算得在时间轮中 槽位置，并将其插入到时间轮合适槽中
	AddTail( apTimeout->pItems + ( apTimeout->llStartIdx + diff ) % apTimeout->iItemSize , apItem );

	return 0;
}

/*
根据当前时间allNow,取出所有超时事件，并合并到apResult中
@param     apTimeout  时间轮
@param     allNow   当前时间
@param     apResult   把所有超时时间事件加入到这个
*/
inline void TakeAllTimeout( stTimeout_t *apTimeout,unsigned long long allNow,stTimeoutItemLink_t *apResult )
{
	if( apTimeout->ullStart == 0 )
	{
		apTimeout->ullStart = allNow;
		apTimeout->llStartIdx = 0;
	}

	//还没有到最近的定时事件，直接返回
	if( allNow < apTimeout->ullStart )
	{
		return ;
	}
	//超时时间小于等于llNow的槽数cnt
	int cnt = allNow - apTimeout->ullStart + 1;
	if( cnt > apTimeout->iItemSize )
	{
		cnt = apTimeout->iItemSize;
	}
	if( cnt < 0 )
	{
		return;
	}
	//cnt个槽
	for( int i = 0;i<cnt;i++)
	{
		int idx = ( apTimeout->llStartIdx + i) % apTimeout->iItemSize;
		//把所有超时事件都放进apResult
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( apResult,apTimeout->pItems + idx  );
	}
	apTimeout->ullStart = allNow;
	apTimeout->llStartIdx += cnt - 1;


}
//一个协程执行回调函数
static int CoRoutineFunc( stCoRoutine_t *co,void * )
{
	if( co->pfn )
	{
		co->pfn( co->arg );
	}
	////标识该协程是否已经结束
	co->cEnd = 1;//只有退出时，才会执行；

	stCoRoutineEnv_t *env = co->env;
	//运行完会从env弹出该协程的控制块
	co_yield_env( env );

	return 0;
}


/*
params   env    当前线程的环境env
params   attr    协程属性
params   pfn     协程工作函数
params   arg     工作函数参数
*/
//根据协程env,新建一个协程
struct stCoRoutine_t *co_create_env( stCoRoutineEnv_t * env, const stCoRoutineAttr_t* attr,
		pfn_co_routine_t pfn,void *arg )
{

	//协程属性，初始化默认属性
	stCoRoutineAttr_t at;
	//用给定的attr去初始化at
	if( attr )
	{
		memcpy( &at,attr,sizeof(at) );
	}
	if( at.stack_size <= 0 )
	{
		at.stack_size = 128 * 1024;
	}
	else if( at.stack_size > 1024 * 1024 * 8 )
	{
		at.stack_size = 1024 * 1024 * 8;
	}

	if( at.stack_size & 0xFFF ) 
	{
		at.stack_size &= ~0xFFF;
		at.stack_size += 0x1000;
	}
	//创建一个协程的控制块
	stCoRoutine_t *lp = (stCoRoutine_t*)malloc( sizeof(stCoRoutine_t) );
	
	memset( lp,0,(long)(sizeof(stCoRoutine_t))); 

	//创建该协程的控制块lp，若为env首次创建,则为main主协程，pfn arg字段都是null
	lp->env = env;
	lp->pfn = pfn;
	lp->arg = arg;

	stStackMem_t* stack_mem = NULL;
	//若采用共享栈
	if( at.share_stack )
	{
		//采用共享栈模式，则获取其中一个共享栈内容
		stack_mem = co_get_stackmem( at.share_stack);
		at.stack_size = at.share_stack->stack_size;
	}
	else
	{
		//没有采用共享栈，则分配内存
		stack_mem = co_alloc_stackmem(at.stack_size);
	}
	//设置协程的栈
	lp->stack_mem = stack_mem;
	//设置协程的ctx：用来保存上下文。ss_sp为协程栈顶指针，ss_size为协程栈大小
	lp->ctx.ss_sp = stack_mem->stack_buffer;
	lp->ctx.ss_size = at.stack_size;
	//
	lp->cStart = 0;
	lp->cEnd = 0;
	lp->cIsMain = 0;
	lp->cEnableSysHook = 0;
	lp->cIsShareStack = at.share_stack != NULL;

	//仅在共享栈才有意义
	lp->save_size = 0;
	lp->save_buffer = NULL;

	return lp;
}
/*
params  ppco  协程控制块
params  attr  协程属性
params   pfn  协程运行函数
params   args  运行函数参数 
*/
//创建一个协程，ppco为协程控制块
int co_create( stCoRoutine_t **ppco,const stCoRoutineAttr_t *attr,pfn_co_routine_t pfn,void *arg )
{
	//如果嵌套调用的协程栈没有被初始化 ， 先初始化协程栈和主协程的控制块
	if( !co_get_curr_thread_env() ) 
	{
		co_init_curr_thread_env();
	}
	//再创建并初始新协程ppco的控制块co
	stCoRoutine_t *co = co_create_env( co_get_curr_thread_env(), attr, pfn,arg );
	*ppco = co;
	return 0;
}
//释放协程co资源
void co_free( stCoRoutine_t *co )
{
	 if (!co->cIsShareStack) 
    {    
        free(co->stack_mem->stack_buffer);
        free(co->stack_mem);
    }   
    //walkerdu fix at 2018-01-20
    //存在内存泄漏
    else 
    {
        if(co->save_buffer)
            free(co->save_buffer);

        if(co->stack_mem->ocupy_co == co)
            co->stack_mem->ocupy_co = NULL;
    }
	free( co );
}

void co_release( stCoRoutine_t *co )
{
	if( co->cEnd )
	{
		free( co );
	}
}

void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co);

//启动协程co
void co_resume( stCoRoutine_t *co )
{
	stCoRoutineEnv_t *env = co->env;
	//当前正在运行的协程
	stCoRoutine_t *lpCurrRoutine = env->pCallStack[ env->iCallStackSize - 1 ];
	//首次运行时，需要人为地准备该协程的上下文context
	if( !co->cStart )
	{
		coctx_make( &co->ctx,(coctx_pfn_t)CoRoutineFunc,co,0 );
		co->cStart = 1;
	}
	//将该协栈控制块压入协程调用栈
	env->pCallStack[ env->iCallStackSize++ ] = co;
	//协程切换
	co_swap( lpCurrRoutine, co );

}

//协程主动退出，让出CPU给last协程
void co_yield_env( stCoRoutineEnv_t *env )
{
	//获取当前协程的父协程
	stCoRoutine_t *last = env->pCallStack[ env->iCallStackSize - 2 ];
	stCoRoutine_t *curr = env->pCallStack[ env->iCallStackSize - 1 ];

	env->iCallStackSize--;
	//协程切换
	co_swap( curr, last);
}

//当前正在运行的协程主动让出cpu
void co_yield_ct()
{

	co_yield_env( co_get_curr_thread_env() );
}
//协程co主动让出cpu
void co_yield( stCoRoutine_t *co )
{
	co_yield_env( co->env );
}

void save_stack_buffer(stCoRoutine_t* ocupy_co)
{
	///copy out
	stStackMem_t* stack_mem = ocupy_co->stack_mem;
	int len = stack_mem->stack_bp - ocupy_co->stack_sp;

	if (ocupy_co->save_buffer)
	{
		free(ocupy_co->save_buffer), ocupy_co->save_buffer = NULL;
	}

	ocupy_co->save_buffer = (char*)malloc(len); //malloc buf;
	ocupy_co->save_size = len;

	memcpy(ocupy_co->save_buffer, ocupy_co->stack_sp, len);
}

//协程切换,将当前运行上下文（寄存器值）保存到curr,从pending_co上下文加载到寄存器中
void co_swap(stCoRoutine_t* curr, stCoRoutine_t* pending_co)
{
 	stCoRoutineEnv_t* env = co_get_curr_thread_env();

	//get curr stack sp
	//很重要，通过申请char变量，就获取了当前栈顶esp,
	char c;
	curr->stack_sp = &c;

	//没有采用共享栈模式 stackful
	if (!pending_co->cIsShareStack)
	{
		env->pending_co = NULL;
		env->ocupy_co = NULL;
	}
	else 
	{
		//采用共享栈模式时，需要切换env中pending_co 、occupy_co
		env->pending_co = pending_co;
		//get last occupy co on the same stack mem
		stCoRoutine_t* ocupy_co = pending_co->stack_mem->ocupy_co;
		//set pending co to ocupy thest stack mem;
		pending_co->stack_mem->ocupy_co = pending_co;

		env->ocupy_co = ocupy_co;
		if (ocupy_co && ocupy_co != pending_co)
		{
			save_stack_buffer(ocupy_co);
		}
	}

	//swap context
	//swap context 切换上下文，保存寄存器的值，汇编实现，此时当前协程阻塞在这儿，等待
	coctx_swap(&(curr->ctx),&(pending_co->ctx) );

	//stack buffer may be overwrite, so get again;当主回到主协程时，执行coctx_swap后，会执行下一条语音；
	stCoRoutineEnv_t* curr_env = co_get_curr_thread_env();
	stCoRoutine_t* update_ocupy_co =  curr_env->ocupy_co;
	stCoRoutine_t* update_pending_co = curr_env->pending_co;
	
	if (update_ocupy_co && update_pending_co && update_ocupy_co != update_pending_co)
	{
		//resume stack buffer
		if (update_pending_co->save_buffer && update_pending_co->save_size > 0)
		{
			//只有采用共享栈模式才会执行，将上次保存的栈内容进行恢复到stack_sp
			memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer, update_pending_co->save_size);
		}
	}
}



//int poll(struct pollfd fds[], nfds_t nfds, int timeout);
// { fd,events,revents }
struct stPollItem_t ;


//stPoll_t继承链表表项.之所以这样，可以需要arg加入到定时事件中
//参考co_poll_inner（）
struct stPoll_t : public stTimeoutItem_t 
{
	struct pollfd *fds;//待检测套接字描述符集合
	nfds_t nfds; // typedef unsigned long int nfds_t;

	stPollItem_t *pPollItems;//存储了待检测的每个文件描述符的信息(参见epoll_event中epoll_data)

	int iAllEventDetach;//标识是否处理了这个对象

	int iEpollFd;//epoll句柄

	int iRaiseCnt;//就绪事件个数
};


struct stPollItem_t : public stTimeoutItem_t
{
	struct pollfd *pSelf;
	stPoll_t *pPoll;

	struct epoll_event stEvent;
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.  
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
//将poll事件类型转化epoll事件类型
static uint32_t PollEvent2Epoll( short events )
{
	uint32_t e = 0;	
	if( events & POLLIN ) 	e |= EPOLLIN;
	if( events & POLLOUT )  e |= EPOLLOUT;
	if( events & POLLHUP ) 	e |= EPOLLHUP;
	if( events & POLLERR )	e |= EPOLLERR;
	if( events & POLLRDNORM ) e |= EPOLLRDNORM;
	if( events & POLLWRNORM ) e |= EPOLLWRNORM;
	return e;
}
static short EpollEvent2Poll( uint32_t events )
{
	short e = 0;	
	if( events & EPOLLIN ) 	e |= POLLIN;
	if( events & EPOLLOUT ) e |= POLLOUT;
	if( events & EPOLLHUP ) e |= POLLHUP;
	if( events & EPOLLERR ) e |= POLLERR;
	if( events & EPOLLRDNORM ) e |= POLLRDNORM;
	if( events & EPOLLWRNORM ) e |= POLLWRNORM;
	return e;
}

static stCoRoutineEnv_t* g_arrCoEnvPerThread[ 204800 ] = { 0 };

// 初始化协程运行环境（协程管理器）
void co_init_curr_thread_env()
{
	//获取当前线程id
	pid_t pid = GetPid();	
	//申请协程环境结构体
	g_arrCoEnvPerThread[ pid ] = (stCoRoutineEnv_t*)calloc( 1,sizeof(stCoRoutineEnv_t) );
	stCoRoutineEnv_t *env = g_arrCoEnvPerThread[ pid ];

	env->iCallStackSize = 0;
	//初始化env时，需要先创建主协程main的协程控制块self
	struct stCoRoutine_t *self = co_create_env( env, NULL, NULL,NULL );
	//标识这是主协程
	self->cIsMain = 1;
	//
	env->pending_co = NULL;
	env->ocupy_co = NULL;

	//主协程上下文清0
	coctx_init( &self->ctx );

	//main主协程控制块压入调用栈
	env->pCallStack[ env->iCallStackSize++ ] = self;

	//申请协程调度器，包括时间轮、epoll、就绪事件超时事件链表
	stCoEpoll_t *ev = AllocEpoll();
	//让env pEpoll字段指向申请的调度器
	SetEpoll( env,ev );
}

//返回协程运行环境
stCoRoutineEnv_t *co_get_curr_thread_env()
{
	return g_arrCoEnvPerThread[ GetPid() ];
}

void OnPollProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

//active事件预处理
void OnPollPreparePfn( stTimeoutItem_t * ap,struct epoll_event &e,stTimeoutItemLink_t *active )
{
	stPollItem_t *lp = (stPollItem_t *)ap;
	lp->pSelf->revents = EpollEvent2Poll( e.events );


	stPoll_t *pPoll = lp->pPoll;
	pPoll->iRaiseCnt++;

	if( !pPoll->iAllEventDetach )
	{
		pPoll->iAllEventDetach = 1;

		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( pPoll );

		AddTail( active,pPoll );

	}
}

/*
调度三种事件：
1、hook的io事件 
2、超时事件
3、用户主动使用poll事件
*/

//调度事件循环：
void co_eventloop( stCoEpoll_t *ctx,pfn_co_eventloop_t pfn,void *arg )
{
	if( !ctx->result )
	{
		ctx->result =  co_epoll_res_alloc( stCoEpoll_t::_EPOLL_SIZE );
	}
	co_epoll_res *result = ctx->result;


	for(;;)
	{	
		//超时时间设置为1ms，所以最长每1ms，就会唤醒,其本质就是调用epoll_wait,只不过是非阻塞
		int ret = co_epoll_wait( ctx->iEpollFd,result,stCoEpoll_t::_EPOLL_SIZE, 1 );

		stTimeoutItemLink_t *active = (ctx->pstActiveList);
		stTimeoutItemLink_t *timeout = (ctx->pstTimeoutList);

		memset( timeout,0,sizeof(stTimeoutItemLink_t) );

		//处理active事件
		for(int i=0;i<ret;i++)
		{
			//取出本次该事件对应的链表表项
			stTimeoutItem_t *item = (stTimeoutItem_t*)result->events[i].data.ptr;
			//如果需要进行预处理
			if( item->pfnPrepare )
			{
				item->pfnPrepare( item,result->events[i],active );
			}
			else
			{
				AddTail( active,item );
			}
		}


		unsigned long long now = GetTickMS();
		//以当前时刻参照，遍历时间轮，放入到超时链表timeout
		TakeAllTimeout( ctx->pTimeout,now,timeout );

		//遍历所有timeout表项，将bTimeout设为true
		stTimeoutItem_t *lp = timeout->head;
		while( lp )
		{
			//printf("raise timeout %p\n",lp);
			lp->bTimeout = true;
			lp = lp->pNext;
		}

		//将tineout合并到active链表中
		Join<stTimeoutItem_t,stTimeoutItemLink_t>( active,timeout );

		lp = active->head;
		//遍历active链表，
		while( lp )
		{

			//从active头部弹出一个节点 
			PopHead<stTimeoutItem_t,stTimeoutItemLink_t>( active );
			if( lp->pfnProcess )
			{

				/*
				使用co_resume恢复协程，从上次暂停的位置继续执行
				*/
				lp->pfnProcess( lp );
			}

			lp = active->head;
		}
		//每轮事件循环 最后调用该函数
		if( pfn )
		{
			if( -1 == pfn( arg ) )
			{
				break;
			}
		}

	}
}

//使用co_resume恢复协程，从上次暂停的位置继续执行
void OnCoroutineEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}

//为线程分配以一个调度器

stCoEpoll_t *AllocEpoll()
{
	stCoEpoll_t *ctx = (stCoEpoll_t*)calloc( 1,sizeof(stCoEpoll_t) );
	//创建epoll
	ctx->iEpollFd = co_epoll_create( stCoEpoll_t::_EPOLL_SIZE );
	//创建时间轮  ms为单位
	ctx->pTimeout = AllocTimeout( 60 * 1000 );
	//就绪事件链表
	ctx->pstActiveList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );
	//超时事件链表
	ctx->pstTimeoutList = (stTimeoutItemLink_t*)calloc( 1,sizeof(stTimeoutItemLink_t) );


	return ctx;
}

//释放调度器ctx
void FreeEpoll( stCoEpoll_t *ctx )
{
	if( ctx )
	{
		free( ctx->pstActiveList );
		free( ctx->pstTimeoutList );
		FreeTimeout( ctx->pTimeout );
		co_epoll_res_free( ctx->result );
	}
	free( ctx );
}

//根据env获得正在运行的协程
stCoRoutine_t *GetCurrCo( stCoRoutineEnv_t *env )
{
	return env->pCallStack[ env->iCallStackSize - 1 ];
}

//获取正在运行的协程
stCoRoutine_t *GetCurrThreadCo( )
{
	stCoRoutineEnv_t *env = co_get_curr_thread_env();
	if( !env ) return 0;
	return GetCurrCo(env);
}



typedef int (*poll_pfn_t)(struct pollfd fds[], nfds_t nfds, int timeout);


//sys_hook需要通过该函数将poll事件注册到epoll中，对外统一接口为poll
/*
params   ctx    epoll调度器epoll的上下文
params  fds[]   要监听的事件描述符，原始poll函数参数
params  nfds   fds长度
params  timeout   等待的时间，毫秒
params  pollfunc  原始poll函数
*/
int co_poll_inner( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout, poll_pfn_t pollfunc)
{
	
	if( timeout > stTimeoutItem_t::eMaxTimeout )
	{
		timeout = stTimeoutItem_t::eMaxTimeout;
	}

	//epoll描述符
	int epfd = ctx->iEpollFd;

	//获取当前协程
	stCoRoutine_t* self = co_self();

	//1.struct change
	//arg记录了当前协程所有I/O事件信息
	stPoll_t& arg = *((stPoll_t*)malloc(sizeof(stPoll_t)));
	memset( &arg,0,sizeof(arg) );

	// arg结构体记录了当前协程所有注册事件信息
	arg.iEpollFd = epfd;
	arg.fds = (pollfd*)calloc(nfds, sizeof(pollfd));
	arg.nfds = nfds;

	stPollItem_t arr[2];
	if( nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack)
	{
		//如果监听的描述符只有1个，并且不是共享栈模型
		arg.pPollItems = arr;
	}	
	else
	{
		arg.pPollItems = (stPollItem_t*)malloc( nfds * sizeof( stPollItem_t ) );
	}
	memset( arg.pPollItems,0,nfds * sizeof(stPollItem_t) );

	//回调函数用来唤醒协程
	arg.pfnProcess = OnPollProcessEvent;
	//回调函数参数  为待唤醒协程的控制块
	arg.pArg = GetCurrCo( co_get_curr_thread_env() ); 
	
	
	//2. add epoll   将当前协程注册事件逐个加入到epoll
	for(nfds_t i=0;i<nfds;i++)
	{
		
		//初始化arg中pPollItems数组
		arg.pPollItems[i].pSelf = arg.fds + i;
		arg.pPollItems[i].pPoll = &arg;

		arg.pPollItems[i].pfnPrepare = OnPollPreparePfn;
		struct epoll_event &ev = arg.pPollItems[i].stEvent;

		if( fds[i].fd > -1 )
		{
			ev.data.ptr = arg.pPollItems + i;
			ev.events = PollEvent2Epoll( fds[i].events );

			//将事件注册到epoll内核事件中
			int ret = co_epoll_ctl( epfd,EPOLL_CTL_ADD, fds[i].fd, &ev );

			//如果注册失败
			if (ret < 0 && errno == EPERM && nfds == 1 && pollfunc != NULL)
			{
				if( arg.pPollItems != arr )
				{
					free( arg.pPollItems );
					arg.pPollItems = NULL;
				}
				free(arg.fds);
				free(&arg);

				//返回原生的poll函数
				return pollfunc(fds, nfds, timeout);
			}
		}
		//if fail,the timeout would work
	}

	//3.add timeout
	//并添加当前协程定时任务
	unsigned long long now = GetTickMS();
	arg.ullExpireTime = now + timeout;
	//
	int ret = AddTimeout( ctx->pTimeout,&arg,now );
	if( ret != 0 )
	{
		co_log_err("CO_ERR: AddTimeout ret %d now %lld timeout %d arg.ullExpireTime %lld",
				ret,now,timeout,arg.ullExpireTime);
		errno = EINVAL;

		if( arg.pPollItems != arr )
		{
			free( arg.pPollItems );
			arg.pPollItems = NULL;
		}
		free(arg.fds);
		free(&arg);

		return -__LINE__;
	}


	//此时，当前协程让出CPU，切换到他的父协程
	co_yield_env( co_get_curr_thread_env() );


	//过段时间后，该协程通过超时被唤醒，需要把arg从链表中删除
	RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &arg );

	//将主协程的注册事件从epoll移除注册
	for(nfds_t i = 0;i < nfds;i++)
	{
		int fd = fds[i].fd;
		if( fd > -1 )
		{
			co_epoll_ctl( epfd,EPOLL_CTL_DEL,fd,&arg.pPollItems[i].stEvent );
		}
		//将实际发生注册事件记录到fds,返回给上层
		fds[i].revents = arg.fds[i].revents;
	}

	//释放内存
	int iRaiseCnt = arg.iRaiseCnt;
	if( arg.pPollItems != arr )
	{
		free( arg.pPollItems );
		arg.pPollItems = NULL;
	}

	free(arg.fds);
	free(&arg);

	return iRaiseCnt;
}

//poll接口，但实际时epoll实现
int	co_poll( stCoEpoll_t *ctx,struct pollfd fds[], nfds_t nfds, int timeout_ms )
{
	return co_poll_inner(ctx, fds, nfds, timeout_ms, NULL);
}

//
void SetEpoll( stCoRoutineEnv_t *env,stCoEpoll_t *ev )
{
	env->pEpoll = ev;
}

//返回当前线程的调度器
stCoEpoll_t *co_get_epoll_ct()
{
	if( !co_get_curr_thread_env() )
	{
		co_init_curr_thread_env();
	}
	return co_get_curr_thread_env()->pEpoll;
}

//
struct stHookPThreadSpec_t
{
	stCoRoutine_t *co;
	void *value;

	enum 
	{
		size = 1024
	};
};


//获取当前协程与key绑定的数据
void *co_getspecific(pthread_key_t key)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_getspecific( key );
	}
	return co->aSpec[ key ].value;
}
//将value绑定到当前协程key中
int co_setspecific(pthread_key_t key, const void *value)
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( !co || co->cIsMain )
	{
		return pthread_setspecific( key,value );
	}
	co->aSpec[ key ].value = (void*)value;
	return 0;
}


//本协程禁用hook机制
void co_disable_hook_sys()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	if( co )
	{
		co->cEnableSysHook = 0;
	}
}

//本协程hook是否打开
bool co_is_enable_sys_hook()
{
	stCoRoutine_t *co = GetCurrThreadCo();
	return ( co && co->cEnableSysHook );
}

//返回当前协程
stCoRoutine_t *co_self()
{
	return GetCurrThreadCo();
}

//co cond
//条件变量等待队列的实现是一个双向链表
struct stCoCond_t;
struct stCoCondItem_t 
{
	stCoCondItem_t *pPrev;
	stCoCondItem_t *pNext;
	stCoCond_t *pLink;

	stTimeoutItem_t timeout;
};
struct stCoCond_t
{
	stCoCondItem_t *head;
	stCoCondItem_t *tail;
};

//根据超时链表项唤醒协程co
static void OnSignalProcessEvent( stTimeoutItem_t * ap )
{
	stCoRoutine_t *co = (stCoRoutine_t*)ap->pArg;
	co_resume( co );
}


stCoCondItem_t *co_cond_pop( stCoCond_t *link );

/* 类似于pthread_cond_signal  唤醒等待队列中一个协程*/
int co_cond_signal( stCoCond_t *si )
{
	//从条件变量链表取出一个协程
	stCoCondItem_t * sp = co_cond_pop( si );
	if( !sp ) 
	{
		return 0;
	}
	//从链表链表移除对应的定时任务
	RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );
	//将其表项调度器中就绪链表
	AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );
	return 0;
}

/*类似于pthread_cond_broadcast唤醒等待队列的所有协程*/
int co_cond_broadcast( stCoCond_t *si )
{
	for(;;)
	{
		stCoCondItem_t * sp = co_cond_pop( si );
		if( !sp ) return 0;

		RemoveFromLink<stTimeoutItem_t,stTimeoutItemLink_t>( &sp->timeout );
		//将唤醒的协程添加到调度器中就绪链表
		AddTail( co_get_curr_thread_env()->pEpoll->pstActiveList,&sp->timeout );
	}

	return 0;
}

/*
params  link 为条件变量双向链表
params  ms  设置超时时间
*/
/*类似于pthread_cond_wait */
int co_cond_timedwait( stCoCond_t *link,int ms )
{
	//申请条件变量链表表项psi
	stCoCondItem_t* psi = (stCoCondItem_t*)calloc(1, sizeof(stCoCondItem_t));
	//设置psi中  timeout字段
	//所关联的协程
	psi->timeout.pArg = GetCurrThreadCo();
	//协程的回调函数
	psi->timeout.pfnProcess = OnSignalProcessEvent;

	//如果设置了定时，还需要添加到时定时管理器 时间轮
	if( ms > 0 )
	{
		unsigned long long now = GetTickMS();
		psi->timeout.ullExpireTime = now + ms;
		//将timeout字段加入到时间轮中
		int ret = AddTimeout( co_get_curr_thread_env()->pEpoll->pTimeout,&psi->timeout,now );
		if( ret != 0 )
		{
			free(psi);
			return ret;
		}
	}
	
	//将psi加入到等待队列中
	AddTail( link, psi);
	//主动让出cpu,此时协程一直阻塞在这里，直到调度器来唤醒
	co_yield_ct();

	RemoveFromLink<stCoCondItem_t,stCoCond_t>( psi );
	free(psi);

	return 0;
}
//申请一个条件变量等待队列
stCoCond_t *co_cond_alloc()
{
	return (stCoCond_t*)calloc( 1,sizeof(stCoCond_t) );
}
int co_cond_free( stCoCond_t * cc )
{
	free( cc );
	return 0;
}
//从cond等待队列中头部取出唤醒协程的表项
stCoCondItem_t *co_cond_pop( stCoCond_t *link )
{
	stCoCondItem_t *p = link->head;
	if( p )
	{
		PopHead<stCoCondItem_t,stCoCond_t>( link );
	}
	return p;
}


