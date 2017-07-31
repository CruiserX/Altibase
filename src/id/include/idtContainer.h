/** 
 *  Copyright (c) 1999~2017, Altibase Corp. and/or its affiliates. All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 
/* **********************************************************************
 *   $Id: 
 *   NAME
 *     idtContainer.h - 스레드 컨테이너
 *
 *   DESCRIPTION
 *     프로젝트 2379로 새로 생성되는 스레드 컨테이너
 *     스레드 컨테이너 
 *
 *   PUBLIC FUNCTION(S)
 *
 *   PRIVATE FUNCTION(S)
 *
 *   NOTES
 *
 *   MODIFIED   (MM/DD/YY)
 ********************************************************************** */

#ifndef O_IDT_CONTAINER_H
#define O_IDT_CONTAINER_H   1

#include <acp.h>
#include <idl.h>
#include <ideErrorMgr.h>
#include <iduMemDefs.h>
#include <iduMutex.h>
#include <iduCond.h>

/* PROJ-2118 sigaltstack */
#ifdef SA_ONSTACK
#include <signal.h>
#if defined(AMD64_LINUX) || defined(XEON_LINUX) || defined(X86_64_LINUX)
#define SIGALTSTK_SIZE (16384)
#else
#define SIGALTSTK_SIZE SIGSTKSZ
#endif
#endif

typedef enum
{
    IDT_CREATING = 0,
    IDT_IDLE,
    IDT_INITIALIZING,
    IDT_RUNNING,
    IDT_FINALIZING,
    IDT_JOINING,
    IDT_FINISHING,
    IDT_ZOMBIE,
    IDT_MAX
} idtThreadStatus;

#define IDT_STRLEN 16
#define IDT_MAX_MSG_SIZE (65536)

class idtBaseThread;

class idtContainer
{
public:
    /*
     * For Fixed Table
     */
    SChar               mIDString[IDT_STRLEN];
    SChar               mIDParent[IDT_STRLEN];
    SChar               mObjectString[IDT_STRLEN];
    SChar*              mStatusString;
    SChar               mAffinityString[128];

    /*
     * Thread handles
     */
    PDL_thread_t        mThreadID;
    PDL_hthread_t       mHandle;
    PDL_thread_t        mParentID;
    idtBaseThread*      mThread;
    IDE_RC              mStartRC;

    /*
     * Thread Specific information
     */
    iduMemClientInfo    mMemInfo[IDU_MEM_UPPERLIMIT];
    ideErrorMgr         mErrorStruct;

    size_t              mStackSize;

    /*
     * CPU and NUMA node number
     */
    SInt                mCPUNo;
    idBool              mIsCPUSet;
    SInt                mNUMANo;
    idBool              mIsNUMASet;

    /*
     * Status
     */
    volatile idtThreadStatus     mThreadStatus;

    /*
     * Information, allocation link, and thread key
     */
    idtContainer*       mAllocLink;
    idtContainer*       mInfoLink;
    static idtContainer mMainThread;
    static iduPeerType  mThreadType;

    /*
     * Static Information -
     * Mutexes and Thread Local Key
     */
    static iduMutex             mAllocLock;
    static iduMutex             mInfoLock;
    static SChar*               mThreadStatusString[IDT_MAX];
    static idBool               mUsePrivateAllocator;
    static idBool               mInitialized;
    static PDL_thread_key_t     mTLS;
    static SInt                 mNoThreads;
    static SInt                 mMaxThreads;

    static void*                staticRunner(void*);
    static void*                clientRunner(void*);
    /*
     * Small blocks will be allocated from thread specific allocator
     */
    iduMemSmall*                mSmallAlloc;
    iduMemTlsf*                 mTlsfAlloc;

    inline PDL_thread_t getTid()
    {
        return mThreadID;
    }

    inline PDL_hthread_t getHandle()
    {
        return mHandle;
    }

    inline idBool isStarted(void)
    {
        return (mThreadStatus != IDT_IDLE)? ID_TRUE:ID_FALSE;
    }

    /*
     * Create, start and join
     */
    IDE_RC          start(void);
    IDE_RC          startServer(void);
    IDE_RC          startClient(void);
    IDE_RC          join(void);
    IDE_RC          destroyThread(void);

    /*
     * Thread affinities
     */
    IDE_RC          setCPUAffinity (SInt aCPUNo);
    IDE_RC          setNUMAAffinity(SInt aNUMANo);

    /*
     * Initialization, destruction
     * Thread specific information
     */
    static void                 initializeBucket(void);
    static IDE_RC               initializeStatic(iduPeerType aType);
    static IDE_RC               initializeStaticContainer(void);
    static IDE_RC               destroyStatic(void);
    static IDE_RC               pop(idtContainer**, idtBaseThread*);
    static idtContainer*        getThreadContainer(void);
    static ideErrorMgr*         getErrorStruct(void);
    static iduMemClientInfo*    getMemClientInfo(void);
    static IDE_RC               expand(SInt aNewMax);

    static idtContainer* getFirstInfo(void)
    {
        return &(idtContainer::mMainThread);
    }

    inline idtContainer* getNextInfo(void)
    {
        return mInfoLink;
    }

    inline void setStatusString(void)
    {
        mStatusString = idtContainer::mThreadStatusString[(SInt)mThreadStatus];
    }

    void makeAffinityString(void);

#if defined(WRS_VXWORKS) 
    static void*    getTaskEntry() {return (void*)staticRunner;}
#endif 

    /*
     * Project-2595
     * Thread specific data
     */
    UInt        mThreadNo;
    UInt        mParentNo;
    size_t      mBucketMsgLength[IDE_LOG_MAX_MODULE];
    SChar       mBucketMsg[IDE_LOG_MAX_MODULE][IDT_MAX_MSG_SIZE];

    inline UInt getThreadNo(void) {return mThreadNo;}
    inline PDL_thread_t getSysThreadNo(void) {return mThreadID;}
    static inline UInt getThreadNumber(void)
    {
        return getThreadContainer()->getThreadNo();
    }
    static inline PDL_thread_t getSysThreadNumber(void)
    {
        return getThreadContainer()->getSysThreadNo();
    }
    void makeBucket(void);
};

#endif 
