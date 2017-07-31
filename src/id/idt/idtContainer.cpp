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
 
/*****************************************************************************
 * $Id:
 ****************************************************************************/

/*****************************************************************************
 *   NAME
 *     idtContainer.cpp - Thread Container class
 *
 *   DESCRIPTION
 *
 *   PUBLIC FUNCTION(S)
 *
 *   PRIVATE FUNCTION(S)
 *
 *   NOTES
 *
 *   MODIFIED   (MM/DD/YY)
 ****************************************************************************/

#include <idtContainer.h>
#include <idtBaseThread.h>
#include <ideLog.h>
#include <idp.h>
#include <iduProperty.h>
#include <iduFixedTable.h>
#include <ideLog.h>
#include <iduVersionDef.h>
#include <iduStack.h>
#include <idtCPUSet.h>

#include <acpSpinWait.h>

/* PROJ-2118 sigaltstack */
#ifdef SA_ONSTACK
#include <signal.h>
#if defined(AMD64_LINUX) || defined(XEON_LINUX) || defined(X86_64_LINUX)
#define SIGALTSTK_SIZE (16384)
#else
#define SIGALTSTK_SIZE SIGSTKSZ
#endif
#endif

/*
 * On SPARC Solaris, I found IDT_SPIN_YIELD worked slightly better for
 * createThread() and join() methods, but ACP_SPIN_WAIT worked order
 * of magitude faster in staticRunner() method and reasonably well in
 * other methods as well.
 */
#define IDT_SPIN_YIELD( aExpr, aSleep )         \
    {                                           \
        PDL_Time_Value sTv;                     \
                                                \
        if ( aSleep > 0 )                       \
        {                                       \
            sTv.msec( aSleep );                 \
        }                                       \
        else                                    \
        {                                       \
            /* do nothing */                    \
        }                                       \
                                                \
        for (;;)                                \
        {                                       \
            if ( aExpr )                        \
            {                                   \
                break;                          \
            }                                   \
            else                                \
            {                                   \
                /* do nothing */                \
            }                                   \
                                                \
            if ( aSleep > 0 )                   \
            {                                   \
                idlOS::sleep( sTv );            \
            }                                   \
            else                                \
            {                                   \
                idlOS::thr_yield();             \
            }                                   \
        }                                       \
    }

class idvSQL;

idBool              idtContainer::mInitialized = ID_FALSE;
iduPeerType         idtContainer::mThreadType  = IDU_CLIENT_TYPE;
idtContainer        idtContainer::mMainThread;
iduMutex            idtContainer::mAllocLock;
iduMutex            idtContainer::mInfoLock;
PDL_thread_key_t    idtContainer::mTLS;

SInt                idtContainer::mNoThreads;
SInt                idtContainer::mMaxThreads;

SChar* idtContainer::mThreadStatusString[IDT_MAX] = 
{
    (SChar*)"CREATING",
    (SChar*)"IDLE",
    (SChar*)"INITIALIZING",
    (SChar*)"RUNNING",
    (SChar*)"FINALIZING",
    (SChar*)"JOINWAIT",
    (SChar*)"FINISHING",
    (SChar*)"ZOMBIE"
};

void* idtContainer::staticRunner(void* aParam)
{
    idtContainer*   sContainer = (idtContainer*)aParam;
    idtBaseThread*  sThread = sContainer->mThread;

    /*
     * Set thread container as thread specific data
     */
    IDE_ASSERT(mThreadType == IDU_SERVER_TYPE);
    IDE_ASSERT(idlOS::thr_setspecific(mTLS, (void*)sContainer) == 0);
    IDE_ASSERT(iduStack::setSigStack() == IDE_SUCCESS);

    /*
     * Initialize resources here
     * to get the nearst memory area from CPU
     */
    idlOS::memset((void*)&(sContainer->mErrorStruct), 0,
                  sizeof(ideErrorMgr));
    sContainer->mSmallAlloc = NULL;
    sContainer->mTlsfAlloc  = NULL;

    if(iduMemMgr::getSmallAlloc(&(sContainer->mSmallAlloc))
       != IDE_SUCCESS)
    {
        sContainer->mSmallAlloc = NULL;
    }
    else
    {
        /* Do nothing */
    }

    if(iduMemMgr::getTlsfAlloc(&(sContainer->mTlsfAlloc))
       != IDE_SUCCESS)
    {
        sContainer->mTlsfAlloc = NULL;
    }
    else
    {
        /* Do nothing */
    }

    sContainer->mThreadStatus = IDT_INITIALIZING;
    iduMemMgr::server_statupdate(IDU_MEM_ID_THREAD_STACK, sContainer->mStackSize, 1);

    (void)idlOS::snprintf(sContainer->mIDString,
                          IDT_STRLEN,
                          "%"ID_XPOINTER_FMT,
                          sContainer->mThreadID);

    sContainer->mStartRC = sThread->initializeThread();
    sContainer->mThreadStatus = IDT_RUNNING;

    /*
     * BUG-44105
     * Unbind thread affinity when a threads starts
     */
    if(idtCPUSet::unbindThread() != ACP_RC_SUCCESS)
    {
        ideLog::log(IDE_SERVER_0,
                    "Warning : Unbinding thread %d(%p) failed.",
                    sContainer->mThreadNo, sContainer);
    }

    if(sContainer->mStartRC == IDE_SUCCESS)
    {
        sThread->run();
        sThread->finalizeThread();
    }
    else
    {
        /* Fall through */
    }

    /* Do not join detached thread */
    if(sThread->mIsJoin == ID_TRUE)
    {
        sContainer->mThreadStatus = IDT_JOINING;
    }
    else
    {

        sContainer->mThreadStatus = IDT_IDLE;
        sContainer->mThread = NULL;
        sContainer->mParentNo = 0;
        sContainer->mParentID = 0;
        (void)idlOS::strcpy(sContainer->mIDParent, "N/A");
        (void)idlOS::strcpy(sContainer->mObjectString, "NULL");
        IDE_TEST(mMainThread.mAllocLock.lock(NULL) != IDE_SUCCESS);
        sContainer->mAllocLink = mMainThread.mAllocLink;
        mMainThread.mAllocLink = sContainer;
        IDE_TEST(mMainThread.mAllocLock.unlock()   != IDE_SUCCESS);
    }

    iduMemMgr::server_statupdate(IDU_MEM_ID_THREAD_STACK,
                                -(SLong)sContainer->mStackSize, -1);


    return NULL;

    IDE_EXCEPTION_END;
    /* this thread will be a zombie */
    sContainer->mThreadStatus = IDT_ZOMBIE;
    iduMemMgr::server_statupdate(IDU_MEM_ID_THREAD_STACK,
                                -(SLong)sContainer->mStackSize, -1);
    return NULL;

}

void* idtContainer::clientRunner(void* aParam)
{
    idtContainer*   sContainer = (idtContainer*)aParam;
    idtBaseThread*  sThread = NULL;

    IDE_ASSERT(mThreadType == IDU_CLIENT_TYPE);
    IDE_ASSERT(idlOS::thr_setspecific(mTLS, (void*)sContainer) == 0);

    idlOS::memset((void*)&(sContainer->mErrorStruct), 0,
                  sizeof(ideErrorMgr));
    ACP_SPIN_WAIT( NULL != sContainer->mThread, -1 );
    sThread = (idtBaseThread*)sContainer->mThread;
    IDE_ASSERT( sThread != NULL );

    sContainer->mStartRC = sThread->initializeThread();

    sContainer->mThreadStatus = IDT_RUNNING;
    if(sContainer->mStartRC == IDE_SUCCESS)
    {
        sThread->run();
        sThread->finalizeThread();
    }

    sContainer->mThreadStatus = IDT_JOINING;

    return NULL;
}

IDE_RC idtContainer::initializeStatic(iduPeerType aType)
{
    SInt i;

    IDE_ASSERT(mInitialized == ID_FALSE);
    mMainThread.mThreadID   = idlOS::thr_self();
    mMainThread.mThread     = NULL;
    mMainThread.mThreadNo   = 0;

    (void)idlOS::snprintf(mMainThread.mIDString,
                          16,
                          "%"ID_XPOINTER_FMT,
                          mMainThread.mThreadID);
    idlOS::strcpy(mMainThread.mObjectString, "MAIN");
    idlOS::strcpy(mMainThread.mIDParent, "N/A");

    idlOS::memcpy((void*)mMainThread.mMemInfo,
                  (void*)iduMemMgr::mClientInfo,
                  sizeof(iduMemClientInfo)*IDU_MEM_UPPERLIMIT);
#if 0
    idlOS::memset((void*)&(mMainThread.mErrorStruct), 0,
                  sizeof(ideErrorMgr));
#endif

    for(i = (SInt)IDU_MIN_CLIENT_COUNT; i < (SInt)IDU_MEM_UPPERLIMIT; i++)
    {
        idlOS::snprintf(mMainThread.mMemInfo[i].mOwner,
                        sizeof(mMainThread.mMemInfo[i].mOwner),
                        "MAIN_THREAD");
        mMainThread.mMemInfo[i].mClientIndex = (iduMemoryClientIndex)i;
    }
    idlOS::strcpy(mMainThread.mMemInfo[IDU_MEM_RESERVED].mName, "RESERVED");

    mMainThread.mCPUNo      = 0;
    mMainThread.mIsCPUSet   = ID_FALSE;
    mMainThread.mNUMANo     = 0;
    mMainThread.mIsNUMASet  = ID_FALSE;

    mMainThread.mThreadStatus     = IDT_RUNNING;

    mMainThread.mAllocLink  = NULL;
    mMainThread.mInfoLink   = NULL;

    IDE_TEST(idlOS::thr_keycreate(&mTLS, NULL) != 0);
    IDE_TEST(idlOS::thr_setspecific(mTLS, (void*)&mMainThread) != 0);

    mInitialized = ID_TRUE;
    mThreadType = aType;
    mNoThreads = 1;
        
    initializeBucket();

    return IDE_SUCCESS;

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC idtContainer::initializeStaticContainer(void)
{
    IDE_RC          sRC;

    IDE_DASSERT(mThreadType == IDU_SERVER_TYPE);

    IDE_TEST_RAISE(mAllocLock.initialize("THREAD_ALLOC_MUTEX",
                                         IDU_MUTEX_KIND_POSIX,
                                         IDV_WAIT_ID_SYSTEM) != IDE_SUCCESS,
                   EMUTEXERROR);
    IDE_TEST_RAISE(mInfoLock.initialize("THREAD_INFO_MUTEX",
                                        IDU_MUTEX_KIND_POSIX,
                                        IDV_WAIT_ID_SYSTEM) != IDE_SUCCESS,
                   EMUTEXERROR);

    /*
     * Read max count of threads
     * When idp::initialize is not called,
     * do not pre-create threads and
     * apply no limit to the count of threads
     */
    sRC = idp::read("MAX_THREAD_COUNT", &mMaxThreads);
    if((sRC == IDE_FAILURE) || (mMaxThreads == 0))
    {
        mMaxThreads = ID_SINT_MAX;
    }
    else
    {
        /* fall through */
    }

    return IDE_SUCCESS;

    IDE_EXCEPTION(EMUTEXERROR)
    {
        IDE_SET(ideSetErrorCode(idERR_FATAL_idc_MUTEX_LOCK));
    }

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC idtContainer::destroyStatic(void)
{
    idtContainer* sBase = idtContainer::getFirstInfo();
    sBase = sBase->getNextInfo();

    while(sBase != NULL)
    {
        IDL_MEM_BARRIER;
        if(sBase->mThreadStatus == IDT_JOINING)
        {
            ideLog::log(IDE_SERVER_0,
                        "Warning : Thread %p with ID %p has not been joined.",
                        sBase, sBase->mThreadID);
        }
        sBase->destroyThread();
        sBase = sBase->getNextInfo();
    }

    (void)mAllocLock.destroy();
    (void)mInfoLock.destroy();

    mInitialized = ID_FALSE;

    return IDE_SUCCESS;
}

IDE_RC idtContainer::pop(idtContainer** aNewThread, idtBaseThread* aThread)
{
    SInt            i;
    idtContainer*   sNewThread;
    idtContainer*   sCurrent;

    /*
     * initializeStatic 이전에 서버 스레드를 생성할 수 없음
     */
    IDE_ASSERT(mInitialized == ID_TRUE || mThreadType == IDU_CLIENT_TYPE);

    if(mInitialized == ID_FALSE)
    {
        /*
         * Enable launch from utility
         */
        IDE_TEST(iduMutexMgr::initializeStatic(IDU_CLIENT_TYPE) != IDE_SUCCESS);
        IDE_TEST(initializeStatic(IDU_CLIENT_TYPE) != IDE_SUCCESS);
    }

    if(mThreadType == IDU_SERVER_TYPE)
    {
        IDE_TEST(mMainThread.mAllocLock.lock(NULL) != IDE_SUCCESS);
        sNewThread = mMainThread.mAllocLink;
        if(sNewThread != NULL)
        {
            mMainThread.mAllocLink = sNewThread->mAllocLink;
        }
        IDE_TEST(mMainThread.mAllocLock.unlock() != IDE_SUCCESS);

        sCurrent = idtContainer::getThreadContainer();

        if(sNewThread == NULL)
        {
            IDE_TEST_RAISE(idtContainer::mNoThreads >=
                           idtContainer::mMaxThreads,
                           ETHREADEXCEED);

            sNewThread = (idtContainer*)iduMemMgr::mallocRaw(sizeof(idtContainer));
            IDE_TEST(sNewThread == NULL);

            idlOS::memcpy((void*)sNewThread->mMemInfo,
                          (void*)iduMemMgr::mClientInfo,
                          sizeof(iduMemClientInfo)*IDU_MEM_UPPERLIMIT);

            IDE_TEST(mMainThread.mInfoLock.lock(NULL) != IDE_SUCCESS);
            sNewThread->mInfoLink = mMainThread.mInfoLink;
            mMainThread.mInfoLink = sNewThread;
            sNewThread->mThreadNo = idtContainer::mNoThreads;
            sNewThread->makeBucket();
            idtContainer::mNoThreads++;
            IDE_TEST(mMainThread.mInfoLock.unlock() != IDE_SUCCESS);

            for(i = (SInt)IDU_MIN_CLIENT_COUNT; i < (SInt)IDU_MEM_UPPERLIMIT; i++)
            {
                idlOS::snprintf(sNewThread->mMemInfo[i].mOwner,
                        sizeof(sNewThread->mMemInfo[i].mOwner),
                        "THREAD_%d", sNewThread->mThreadNo);
                sNewThread->mMemInfo[i].mClientIndex = (iduMemoryClientIndex)i;
            }
            idlOS::strcpy(sNewThread->mMemInfo[IDU_MEM_RESERVED].mName, "RESERVED");
        }
        else
        {
            /* do nothing */
        }
        
        sNewThread->mParentNo = sCurrent->getThreadNo();
        sNewThread->mParentID = sCurrent->getTid();
        sNewThread->mThread = aThread;

        (void)idlOS::snprintf(sNewThread->mIDParent,
                              16,
                              "%"ID_XPOINTER_FMT,
                              sNewThread->mParentID);
    }
    else
    {
        sNewThread = (idtContainer*)idlOS::malloc(sizeof(idtContainer));
        /* BUG-39551 */
        IDE_TEST(sNewThread == NULL);
        sNewThread->mThread = aThread;
    }

    *aNewThread = sNewThread;
    return IDE_SUCCESS;

    IDE_EXCEPTION(ETHREADEXCEED)
    {
        IDE_SET(ideSetErrorCode(idERR_IGNORE_THREADCOUNT_EXCEEDED,
                                idtContainer::mMaxThreads));
    }

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC idtContainer::start(void)
{
    return (mThreadType == IDU_CLIENT_TYPE)?
        startClient(): 
        startServer();
}

IDE_RC idtContainer::startClient(void)
{
    mThread->mContainer = this;

    mThreadStatus   = IDT_CREATING;
    /*
     * BUGBUG : Replace these codes with
     * CPU or NUMA affinity functions
     */
    mCPUNo      = 0;
    mIsCPUSet   = ID_FALSE;
    mNUMANo     = 0;
    mIsNUMASet  = ID_FALSE;

    mStackSize  = IDU_DEFAULT_THREAD_STACK_SIZE;

    IDE_TEST(idlOS::thr_create(clientRunner,
                               this,
                               THR_JOINABLE,
                               &mThreadID,
                               &mHandle,
                               PDL_DEFAULT_THREAD_PRIORITY,
                               NULL,
                               mStackSize) != 0);
    return IDE_SUCCESS;

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC idtContainer::startServer(void)
{
    mThread->mContainer = this;
    mThreadStatus = IDT_CREATING;

    (void)idlOS::snprintf(mObjectString,
                          IDT_STRLEN,
                          "%"ID_XPOINTER_FMT,
                          mThread);

    mStackSize  = IDU_DEFAULT_THREAD_STACK_SIZE;


    IDE_TEST(idlOS::thr_create(staticRunner,
                               this,
                               (mThread->mIsJoin == ID_TRUE)?
                                    IDT_JOINABLE : IDT_DETACHED,
                               &mThreadID,
                               &mHandle,
                               PDL_DEFAULT_THREAD_PRIORITY,
                               NULL,
                               mStackSize) != 0);

    /*
     * Wait idle status
     */
    ACP_SPIN_WAIT( ( mThreadStatus != IDT_CREATING ) &&
                   ( mThreadStatus != IDT_INITIALIZING ) , -1 );

    return mStartRC;

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC idtContainer::join(void)
{
    IDE_TEST(idlOS::thr_join(mHandle, NULL) != 0);

    if(mThreadType == IDU_CLIENT_TYPE)
    {
        idlOS::free(this);
    }
    else
    {
        mThread = NULL;
        mThreadStatus = IDT_IDLE;
        mParentNo = 0;
        mParentID = 0;

        (void)idlOS::strcpy(mObjectString, "NULL");
        (void)idlOS::memset(mIDString, 0, IDT_STRLEN);
        (void)idlOS::memset(mIDParent, 0, IDT_STRLEN);
        (void)idlOS::strcpy(mIDParent, "N/A");

        IDE_TEST(mMainThread.mAllocLock.lock(NULL) != IDE_SUCCESS);
        mAllocLink = mMainThread.mAllocLink;
        mMainThread.mAllocLink = this;
        IDE_TEST(mMainThread.mAllocLock.unlock()   != IDE_SUCCESS);
    }

    return IDE_SUCCESS;

    IDE_EXCEPTION_END;
    mThreadStatus = IDT_ZOMBIE;
    return IDE_FAILURE;
}

IDE_RC idtContainer::destroyThread(void)
{
    if(mThreadStatus == IDT_JOINING)
    {
        (void)join();
    }

    return IDE_SUCCESS;
}

IDE_RC idtContainer::setCPUAffinity (SInt aCPUNo)
{
    PDL_UNUSED_ARG(aCPUNo);
    return IDE_SUCCESS;
}

IDE_RC idtContainer::setNUMAAffinity(SInt aNUMANo)
{
    PDL_UNUSED_ARG(aNUMANo);
    return IDE_SUCCESS;
}

idtContainer* idtContainer::getThreadContainer(void)
{
    idtContainer* sContainer;

    if(idtContainer::mInitialized == ID_TRUE)
    {
        IDE_ASSERT(idlOS::thr_getspecific(idtContainer::mTLS, (void**)&sContainer) == 0);
    }
    else
    {
        sContainer = &(mMainThread);
    }

    return sContainer;
}


ideErrorMgr* idtContainer::getErrorStruct(void)
{
    idtContainer* sContainer;
    sContainer = idtContainer::getThreadContainer();
    return (sContainer==NULL)? NULL:&(sContainer->mErrorStruct);
}

iduMemClientInfo* idtContainer::getMemClientInfo(void)
{
    idtContainer* sContainer;
    sContainer = idtContainer::getThreadContainer();
    return (sContainer==NULL)? NULL:&(sContainer->mMemInfo[0]);
}

IDE_RC idtContainer::expand(SInt aNewMax)
{
    IDE_TEST_RAISE(aNewMax <= mMaxThreads, ECANNOTSHRINK);
    mMaxThreads = aNewMax;
    return IDE_SUCCESS;

    IDE_EXCEPTION(ECANNOTSHRINK)
    {
    }

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

void idtContainer::makeBucket(void)
{
    /*
     * Prepare for bucket list
     */
    SInt i;

    for(i = IDE_ERR; i < IDE_LOG_MAX_MODULE; i++)
    {
        mBucketMsgLength[i] = 0;
    }

    mBucketMsgLength[IDE_SERVER] = idlOS::snprintf(mBucketMsg[IDE_SERVER],
                                                   IDT_MAX_MSG_SIZE,
                                                   "ALTIBASE %s\n"
                                                   "\tProduct version  : %s\n"
                                                   "\tCPU              : %s\n"
                                                   "\tOperating System : %s\n"
                                                   "\tProcess ID       : %d\n"
                                                   "\tThread No        : %d\n",
                                                   ALTIBASE_PRODUCT,
                                                   IDU_ALTIBASE_VERSION_STRING,
                                                   ALTI_CFG_CPU,
                                                   OS_SYSTEM_TYPE,
                                                   idlOS::getpid(),
                                                   getThreadNo());
}

void idtContainer::initializeBucket()
{
    mMainThread.makeBucket();
}

void idtContainer::makeAffinityString(void)
{
    idtBaseThread* sThread;

    sThread = (idtBaseThread*)mThread;

    if(mThread == NULL)
    {
        idlOS::strcpy(mAffinityString, "N/A");
    }
    else
    {
        sThread->mAffinity.dumpCPUsToString(mAffinityString, 128);
    }
}

#if !defined(SMALL_FOOTPRINT) || defined(WRS_VXWORKS)

/*
 * Project 2379
 * Fixed Table to Retrieve Thread Container Information
 */

static iduFixedTableColDesc gThreadContainerColDesc[] =
{
    {
        (SChar *)"THREAD_NO",
        offsetof(idtContainer, mThreadNo),
        IDU_FT_SIZEOF(idtContainer, mThreadNo),
        IDU_FT_TYPE_INTEGER,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        (SChar *)"PARENT_NO",
        offsetof(idtContainer, mParentNo),
        IDU_FT_SIZEOF(idtContainer, mParentNo),
        IDU_FT_TYPE_INTEGER,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        (SChar *)"THREAD_ID",
        offsetof(idtContainer, mIDString),
        IDU_FT_SIZEOF(idtContainer, mIDString),
        IDU_FT_TYPE_CHAR,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        (SChar *)"PARENT_ID",
        offsetof(idtContainer, mIDParent),
        IDU_FT_SIZEOF(idtContainer, mIDParent),
        IDU_FT_TYPE_CHAR,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        (SChar *)"THREAD_OBJECT",
        offsetof(idtContainer, mObjectString),
        IDU_FT_SIZEOF(idtContainer, mObjectString),
        IDU_FT_TYPE_CHAR,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        (SChar *)"STATUS",
        offsetof(idtContainer, mStatusString),
        IDT_STRLEN,
        IDU_FT_TYPE_CHAR | IDU_FT_TYPE_POINTER,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        (SChar *)"AFFINITY",
        offsetof(idtContainer, mAffinityString),
        128,
        IDU_FT_TYPE_CHAR,
        NULL,
        0, 0,NULL // for internal use
    },
    {
        NULL,
        0,
        0,
        IDU_FT_TYPE_CHAR,
        NULL,
        0, 0,NULL // for internal use
    }
};

static IDE_RC buildRecordForThreadContainer(idvSQL      *,
                                            void        *aHeader,
                                            void        * /* aDumpObj */,
                                            iduFixedTableMemory *aMemory)
{
    idtContainer* sBase = idtContainer::getFirstInfo();

    do
    {
        sBase->setStatusString();
        sBase->makeAffinityString();

        IDE_TEST(iduFixedTable::buildRecord(aHeader,
                                            aMemory,
                                            (void*)sBase)
                 != IDE_SUCCESS);

        sBase = sBase->getNextInfo();
    } while(sBase != NULL);

    return IDE_SUCCESS;

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}


iduFixedTableDesc gThreadContainerTableDesc =
{
    (SChar *)"X$THREADS",
    buildRecordForThreadContainer,
    gThreadContainerColDesc,
    IDU_STARTUP_META,
    0,
    0,
    IDU_FT_DESC_TRANS_NOT_USE,
    NULL
};

#endif

