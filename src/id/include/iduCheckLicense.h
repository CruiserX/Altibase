/*****************************************************************************
 * Copyright 1999-2000, ALTIBASE Corporation or its subsidiaries.
 * All rights reserved.
 ****************************************************************************/

/*****************************************************************************
 * $Id: iduCheckLicense.h 75550 2016-05-20 12:32:13Z djin $
 ****************************************************************************/

#include <acp.h>
#include <idTypes.h>

#ifndef _O_IDU_CHECK_LICENSE_H_
#define _O_IDU_CHECK_LICENSE_H_ 1

#define KEY         (UChar*)"aeroKesabitla99916102Ltd"
#define BACKDOOR    (SChar*)"679AD49E23696A5C9B5278F7A8AFAD932E8D5FAEFD38119B9A80AF7CF90552D6"
#define ANYHOST     (SChar*)"RTBASE"

#define COMMUNITYEDITION    ((UChar)(0))
#define STANDARDEDITION     ((UChar)(1))
#define ENTERPRISEEDITION   ((UChar)(2))
#define TRIALEDITION        ((UChar)(3))

typedef struct iduLicenseHeader
{
    UChar mHeader;          /*  1 : Header - random value */
    SChar mMajorVersion;    /*  2 : Product Version */
    SChar mMinorVersion;    /*  3 : Product Version */
    UChar mExpire[4];       /*  7 : Expiry Date */
    UChar mType;            /*  8 : Type of License */
    UChar mID[6];           /* 14 : MAC Address */
    UChar mMemMax[4];       /* 18 : MEM_MAX_DB_SIZE */
    UChar mDiskMax[4];      /* 22 : DISK_MAX_DB_SIZE */
    UChar mCoreMax[2];      /* 24 : Count of CORE */
    UChar mIssued[6];       /* 30 : Issued Date */
    UChar mCRC;             /* 31 : CRC */
    UChar mTailer;          /* 32 : Tailer - same with header */
} iduLicenseHeader;

struct iduLicense
{
    iduLicense();

    static IDE_RC  initializeStatic(void);

    IDE_RC  load(const SChar* = NULL);
    idBool  check(void);
    IDE_RC  encode(SChar*);
    IDE_RC  decode(const SChar*);
    idBool  checkValid(void);

    IDE_RC  applyMax(void);

    iduLicenseHeader    mLicense;           /* License */
    SChar               mPath[ID_MAX_FILE_NAME];    /* Pathname of license file */
    ULong               mMemMax;            /* MEM_MAX_DB_SIZE */
    ULong               mDiskMax;           /* DISK_MAX_DB_SIZE */
    ULong               mExpire;
    ULong               mIssued;
    UInt                mMaxCores;
    UInt                mMaxNUMAs;

    static acp_mac_addr_t      mMacAddr[ID_MAX_HOST_ID_NUM];
    static UInt                mNoMac;
};

class iduCheckLicense
{
public:
    static IDE_RC initializeStatic(void);
    static IDE_RC check(void);
    static IDE_RC update(void);
    static IDE_RC getHostUniqueString(SChar*, UInt);
    static inline UInt getMaxCores(void)
    {
        return mLicense.mMaxCores;
    }
    static inline UChar getMaxNUMAs(void)
    {
        return mLicense.mMaxNUMAs;
    }

    static iduLicense mLicense;
};

#endif

