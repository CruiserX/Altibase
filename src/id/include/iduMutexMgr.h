/***********************************************************************
 * Copyright 1999-2000, RTBase Corporation or its subsidiaries.
 * All rights reserved.
 **********************************************************************/

/***********************************************************************
 * $Id: iduMutexMgr.h 66405 2014-08-13 07:15:26Z djin $
 **********************************************************************/
#ifndef _O_IDU_MUTEX_MGR_H_
#define _O_IDU_MUTEX_MGR_H_ 1

#include <iduMemDefs.h>
#include <idl.h>
#include <iduMutexEntry.h>

class iduMemSmall;
class iduMemPool;

class iduMutexMgr
{
private:
    /*
     * Project 2379 - Limit max count of mutex
     */
    static IDE_RC makeNewEntry(iduMutexEntry**, iduMutexKind);

    static iduMutexEntry    mPosixEntry;
    static iduMutexEntry    mNativeEntry;
    static iduMutexEntry    mInfoEntry;
    static UInt             mAllocCount;
    static UInt             mMutexCount;

    //fix PROJ-1749
    static iduMutexOP*      mMutexOpArrayServer[IDU_MUTEX_KIND_MAX];
    static iduMutexOP*      mMutexOpArrayClient[IDU_MUTEX_KIND_MAX];
    
    //fix PROJ-1749
    static iduPeerType      mMutexMgrType;

    /*
     * Project 2408 - Memory allocator renewal
     */
    static IDE_RC           allocEntry(iduMutexEntry**);
    static IDE_RC           freeEntry(iduMutexEntry*);
    static iduMemSmall      mMutexPool;
    static idBool           mUsePool;

    
public:
    static void   lockPosix()       { mPosixEntry.lock(NULL);   }
    static void   unlockPosix()     { mPosixEntry.unlock();     }
    static void   lockNative()      { mNativeEntry.lock(NULL);  }
    static void   unlockNative()    { mNativeEntry.unlock();    }
    static void   lockInfo()        { mInfoEntry.lock(NULL);    }
    static void   unlockInfo()      { mInfoEntry.unlock();      }

    static IDE_RC initializeStatic(iduPeerType aMutexMgrType);
    static IDE_RC destroyStatic();
    
    static IDE_RC alloc(iduMutexEntry **aEntry, iduMutexKind aKind);
    static IDE_RC free(iduMutexEntry *aEntry);

    static iduMutexEntry* getRoot() { return &mPosixEntry; }
    static iduMutexEntry* getInfo() { return &mInfoEntry; }
    static UInt   getMutexCount() { return (mMutexCount); }
   
    //fix PROJ-1749 
    static iduMutexOP* getMutexOP( iduMutexKind aKind )
           { 
               if (mMutexMgrType == IDU_SERVER_TYPE) 
               {
                   return mMutexOpArrayServer[aKind];
               }
               else
               {
                   return mMutexOpArrayClient[aKind];
               }
           }
};

#endif	// _O_MUTEX_MGR_H_
