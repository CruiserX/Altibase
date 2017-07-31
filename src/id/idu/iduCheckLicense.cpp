/*****************************************************************************
 * Copyright 1999-2000, ALTIBASE Corporation or its subsidiaries.
 * All rights reserved.
 ****************************************************************************/

/*****************************************************************************
 * $Id: iduCheckLicense.cpp 80586 2017-07-24 00:57:33Z yoonhee.kim $
 ****************************************************************************/

#include <acp.h>
#include <idl.h>
#include <idErrorCode.h>
#include <ideCallback.h>
#include <ideErrorMgr.h>
#include <idsDES.h>
#include <iduCheckLicense.h>
#include <ideLog.h>
#include <idp.h>
#include <iduVersion.h>
#include <idt.h>

static const SChar * const DEFAULT_LICENSE = IDL_FILE_SEPARATORS"conf"IDL_FILE_SEPARATORS"license";

acp_mac_addr_t  iduLicense::mMacAddr[ID_MAX_HOST_ID_NUM];
UInt            iduLicense::mNoMac;
iduLicense      iduCheckLicense::mLicense;

iduLicense::iduLicense()
{
    mMemMax  = ID_ULONG(1) * 1024 * 1024 * 1024 * 1024;
    mDiskMax = ID_ULONG(5) * 1024 * 1024 * 1024 * 1024;

    idlOS::memset(&mLicense, 0, sizeof(mLicense));
    idlOS::memset(mPath,     0, ID_MAX_FILE_NAME);
}

IDE_RC iduLicense::initializeStatic(void)
{
    acp_rc_t    sRC;

    UInt        i;
    SChar       sTmpBuffer[256];
    SChar       sMsgBuffer[16384];

    sRC = acpSysGetMacAddress(mMacAddr, ID_MAX_HOST_ID_NUM, &mNoMac);
    IDE_TEST_RAISE(ACP_RC_NOT_SUCCESS(sRC), EGETMAC);
    IDE_TEST_RAISE(mNoMac == 0, EGETMAC);

    idlOS::strcpy(sMsgBuffer, "Enumerating authorization keys\n");
    for(i = 0; i < mNoMac; i++)
    {
        idlOS::snprintf(sTmpBuffer, sizeof(sTmpBuffer),
                        "\tMAC Address [%3d] : [%02X:%02X:%02X:%02X:%02X:%02X]\n",
                        i,
                        (UChar)mMacAddr[i].mAddr[0],
                        (UChar)mMacAddr[i].mAddr[1],
                        (UChar)mMacAddr[i].mAddr[2],
                        (UChar)mMacAddr[i].mAddr[3],
                        (UChar)mMacAddr[i].mAddr[4],
                        (UChar)mMacAddr[i].mAddr[5]);
        idlOS::strcat(sMsgBuffer, sTmpBuffer);
    }

    ideLog::log(IDE_SERVER_0, sMsgBuffer);

    return IDE_SUCCESS;

    IDE_EXCEPTION(EGETMAC)
    {
        IDE_CALLBACK_SEND_MSG("[ERROR] Unable to detect MAC addresses!");
    }

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC iduLicense::load(const SChar* aPath)
{
#ifdef ALTI_CFG_EDITION_DISK    /* PROJ-2639 Altibase Disk Edition */

    PDL_UNUSED_ARG( aPath );

    mMemMax   = ID_ULONG_MAX;
    mDiskMax  = ID_ULONG_MAX;
    mExpire   = ID_ULONG_MAX;   // License Update를 실패시켜야 하므로, ID_ULONG_MAX 이어야 한다.
    mIssued   = 0;              // 미사용
    mMaxCores = ACP_PSET_MAX_CPU;
    mMaxNUMAs = IDT_MAX_NUMA_NODES;

    IDE_CALLBACK_SEND_SYM( "Server is Disk Edition.\n" );
    ideLog::log( IDE_SERVER_0, "MEM_MAX_DB_SIZE is UNLIMITED." );
    ideLog::log( IDE_SERVER_0, "DISK_MAX_DB_SIZE is UNLIMITED." );

    return IDE_SUCCESS;

#elif ALTI_CFG_EDITION_OPEN    /*BUG-45136*/
    PDL_UNUSED_ARG( aPath );

    mMemMax   = ID_ULONG_MAX;
    mDiskMax  = ID_ULONG_MAX;
    mExpire   = ID_ULONG_MAX;   
    mIssued   = 0;             
    mMaxCores = ACP_PSET_MAX_CPU;
    mMaxNUMAs = IDT_MAX_NUMA_NODES;
    IDE_CALLBACK_SEND_SYM( "Server is Open Edition.\n" );
    ideLog::log( IDE_SERVER_0, "MEM_MAX_DB_SIZE is UNLIMITED." );
    ideLog::log( IDE_SERVER_0, "DISK_MAX_DB_SIZE is UNLIMITED." );
    return IDE_SUCCESS;
#else

    PDL_HANDLE  sFile;
    idBool      sValid;
    SChar       sLine[sizeof(iduLicenseHeader) * 4 + 1];
    SChar       sMsgBuffer[16384];

    if(aPath == NULL)
    {
        /* use default path */
        idlOS::snprintf(mPath, ID_MAX_FILE_NAME, "%s%s",
                        idp::getHomeDir(), DEFAULT_LICENSE);
    }
    else
    {
        /* use aPath */
        idlOS::strcpy(mPath, aPath);
    }

    sValid   = ID_FALSE;

    sFile = idf::open(mPath, O_RDONLY);

    /*BUG-45014 V7에서 license key 없을때, CE동작하는기능
                (메모리와 디스크 사이즈 제한으로 동작하는 기능)을 제거합니다. */
    IDE_TEST_RAISE( sFile == PDL_INVALID_HANDLE, NOVALIDLICENSE );

    idlOS::memset(sLine, 0, sizeof(sLine));
    while(idf::fdgets(sLine, sizeof(sLine) * 4 + 1, sFile) != NULL)
    {
        /*********************
         * (0) Pass comment
         ********************/
        if(sLine[0] == '#' || sLine[0] == '\n')
        {
            continue;
        }
        else
        {
            /* Fall through */
        }

        //--------------------
        // (1) Check Back Door
        //--------------------
        IDE_TEST_CONT(idlOS::strncmp(sLine, BACKDOOR, idlOS::strlen(BACKDOOR)) == 0,
                      SUPERLICENSE);

        if(decode(sLine) == IDE_SUCCESS)
        {
            IDE_TEST_CONT(checkValid() != ID_TRUE, CORRUPTED);

            if(mLicense.mType == TRIALEDITION)
            {
                idlOS::snprintf(sMsgBuffer, sizeof(sMsgBuffer),
                                "\tTrial License with Expiry %u\n",
                                (ULong)mLicense.mExpire[0] << 24 |
                                (ULong)mLicense.mExpire[1] << 16 |
                                (ULong)mLicense.mExpire[2] <<  8 |
                                (ULong)mLicense.mExpire[3]);
            }
            else
            {
                idlOS::snprintf(sMsgBuffer, sizeof(sMsgBuffer),
                                "\tLicense with [%02X:%02X:%02X:%02X:%02X:%02X]"
                                " Expiry %u\n",
                                mLicense.mID[0],
                                mLicense.mID[1],
                                mLicense.mID[2],
                                mLicense.mID[3],
                                mLicense.mID[4],
                                mLicense.mID[5],
                                (ULong)mLicense.mExpire[0] << 24 |
                                (ULong)mLicense.mExpire[1] << 16 |
                                (ULong)mLicense.mExpire[2] <<  8 |
                                (ULong)mLicense.mExpire[3]);
            }
            ideLog::log(IDE_SERVER_0, sMsgBuffer);

            if(check() == ID_TRUE)
            {
                sValid = ID_TRUE;
                break;
            }
            else
            {
                /* continue */
            }
        }
        else
        {
            /* continue */
        }
        continue;

        IDE_EXCEPTION_CONT(CORRUPTED)
        {
            ideLog::log(IDE_SERVER_0, "Corrupted license string!\n");
            IDE_CALLBACK_SEND_SYM("Corrupted license string!\n");
        }
    }

    IDE_TEST_RAISE(sValid != ID_TRUE, NOVALIDLICENSE);

    ideLog::log(IDE_SERVER_0, "Valid License! Launching Server!\n");
    (void)idf::close(sFile);
    return IDE_SUCCESS;

    IDE_EXCEPTION_CONT(SUPERLICENSE)
    {
        mMemMax   = ID_ULONG_MAX;
        mDiskMax  = ID_ULONG_MAX;
        mExpire   = ID_ULONG_MAX;
        mIssued   = ID_ULONG_MAX;
        mMaxCores = ACP_PSET_MAX_CPU;
        mMaxNUMAs = IDT_MAX_NUMA_NODES;

        IDE_CALLBACK_SEND_SYM("You are using super license.\n"
                              "This is illegal unless you are a crew "
                              "of Altibase Co. Ltd.\n");
    }

    (void)idf::close(sFile);
    return IDE_SUCCESS;

    IDE_EXCEPTION(NOVALIDLICENSE)
    {
        IDE_CALLBACK_SEND_SYM("No valid license present!\n");
    }

    IDE_EXCEPTION_END;
    return IDE_FAILURE;

#endif  /* ALTI_CFG_EDITION_DISK */
}

idBool iduLicense::check(void)
{
    UInt            i;

    UInt            sCurrent;
    UInt            sExpiry;
    time_t          sTime;

    struct tm       sBroken;
    PDL_Time_Value  sNow;
    SChar           sMsgBuffer[16384];


    if(mLicense.mType == TRIALEDITION)
    {
        mMemMax   = ID_ULONG_MAX;
        mDiskMax  = ID_ULONG_MAX;
        mMaxCores = ACP_PSET_MAX_CPU;
        mMaxNUMAs = IDT_MAX_NUMA_NODES;
    }
    else
    {
        for(i = 0; i < mNoMac; i++)
        {
            if(idlOS::memcmp(mLicense.mID, mMacAddr[i].mAddr, 6) == 0)
            {
                break;
            }
            else
            {
                idlOS::snprintf(sMsgBuffer, sizeof(sMsgBuffer),
                                "\t[%02X:%02X:%02X:%02X:%02X:%02X] does not match\n",
                                mLicense.mID[0],
                                mLicense.mID[1],
                                mLicense.mID[2],
                                mLicense.mID[3],
                                mLicense.mID[4],
                                mLicense.mID[5]);
                ideLog::log(IDE_SERVER_0, sMsgBuffer);
            }
        }
        IDE_TEST_RAISE(i == mNoMac, ENOMACMATCH);

        if(mLicense.mType == ENTERPRISEEDITION)
        {
            mMemMax     = ID_ULONG_MAX;
            mDiskMax    = ID_ULONG_MAX;

            mMaxCores   =
                ((UShort)mLicense.mCoreMax[0] << 8) |
                ((UShort)mLicense.mCoreMax[1]);
            mMaxCores = (mMaxCores == 0)? ACP_PSET_MAX_CPU:mMaxCores;
            mMaxNUMAs = IDT_MAX_NUMA_NODES;
        }
        else
        {
            mMemMax   = (ULong)mLicense.mMemMax[0] << 24 |
                        (ULong)mLicense.mMemMax[1] << 16 |
                        (ULong)mLicense.mMemMax[2] <<  8 |
                        (ULong)mLicense.mMemMax[3];
            mMemMax  *= 1024 * 1024 * 1024;
            mDiskMax  = (ULong)mLicense.mDiskMax[0] << 24 |
                        (ULong)mLicense.mDiskMax[1] << 16 |
                        (ULong)mLicense.mDiskMax[2] <<  8 |
                        (ULong)mLicense.mDiskMax[3];
            mDiskMax *= 1024 * 1024 * 1024;

            mMaxCores   =
                ((UShort)mLicense.mCoreMax[0] << 8) |
                ((UShort)mLicense.mCoreMax[1]);
            mMaxCores = (mMaxCores == 0)? ACP_PSET_MAX_CPU:mMaxCores;
            mMaxNUMAs = 2;
        }
    }

    /* 
     * MAC Address match.
     * Check expiry date.
     */
    sNow = idlOS::gettimeofday();
    sTime = (time_t)sNow.sec();
    idlOS::localtime_r(&sTime, &sBroken);
    sCurrent =
        ((sBroken.tm_year  + 1900) * 10000) +
        ((sBroken.tm_mon + 1) * 100) +
        ((sBroken.tm_mday));

    sExpiry = (ULong)mLicense.mExpire[0] << 24 |
              (ULong)mLicense.mExpire[1] << 16 |
              (ULong)mLicense.mExpire[2] <<  8 |
              (ULong)mLicense.mExpire[3];
    IDE_TEST_RAISE(sExpiry < sCurrent, EEXPIRED);
    mExpire = sExpiry;

    return ID_TRUE;

    IDE_EXCEPTION(ENOMACMATCH)
    {
        ideLog::log(IDE_SERVER_0, "MAC Address does not match!\n");
        IDE_CALLBACK_SEND_SYM("MAC Address does not match!\n");
    }

    IDE_EXCEPTION(EEXPIRED)
    {
        idlOS::snprintf(sMsgBuffer, sizeof(sMsgBuffer),
                        "\tLicense expired (%u) < system time (%u)\n",
                        sExpiry, sCurrent);
        ideLog::log(IDE_SERVER_0, sMsgBuffer);
        IDE_CALLBACK_SEND_SYM("License expired!\n");
    }

    IDE_EXCEPTION_END;
    return ID_FALSE;
}

IDE_RC iduLicense::encode(SChar* aTarget)
{
    SInt                i;
    UInt                sTotal;
    SInt                sRand;
    UChar*              sLicense;
    UChar               sPlainText[sizeof(mLicense)];
    UChar               sCypherText[sizeof(mLicense)];
    idsDES              sDes;

    sRand = (UInt)idlOS::getpid() % 256;
    mLicense.mHeader = (UChar)sRand;
    mLicense.mTailer = (UChar)sRand;

    sLicense = (UChar*)&mLicense;

    sTotal = 0;

    for(i = 1; i < (SInt)sizeof(mLicense) - 2; i++)
    {
        sTotal += (UInt)sLicense[i];
    }
    mLicense.mCRC = (UChar)(sTotal % 256);

    idlOS::memcpy(sPlainText, &mLicense, sizeof(mLicense));
    for(i = 1; i < (SInt)sizeof(mLicense) - 1; i++)
    {
        sPlainText[i] += (UChar)(sRand);
    }

    idlOS::memcpy(sCypherText, sPlainText, sizeof(mLicense));
    for(i = 0; i < (SInt)sizeof(mLicense); i += 8)
    {
        sDes.tripleDes((UChar *)&(sCypherText[i]),
                       (UChar *)&(sCypherText[i]),
                       KEY,
                       IDS_ENCODE);
    }

    sDes.bin2ascii((SChar*)sCypherText, aTarget, sizeof(mLicense));
    aTarget[sizeof(mLicense) * 2] = 0;

    return IDE_SUCCESS;

    /*
    IDE_EXCEPTION_END;
    return IDE_FAILURE;
    */
}

IDE_RC iduLicense::decode(const SChar* aSource)
{
    idsDES  sDes;
    SInt    i;
    UChar   sPlainText[sizeof(mLicense)];
    UChar   sCypherText[sizeof(mLicense)];

    sDes.ascii2bin((SChar*)aSource, (SChar*)sCypherText, sizeof(mLicense));

    for(i = 0; i < (SInt)sizeof(mLicense); i += 8)
    {
        sDes.tripleDes((UChar *)&(sCypherText[i]),
                       (UChar *)&(sCypherText[i]),
                       KEY,
                       IDS_DECODE);
    }

    idlOS::memcpy(sPlainText, sCypherText, sizeof(mLicense));
    for(i = 1; i < (SInt)sizeof(mLicense) - 1; i++)
    {
        sPlainText[i] -= sPlainText[0];
    }
    idlOS::memcpy(&mLicense, sPlainText, sizeof(mLicense));

    return IDE_SUCCESS;
}

idBool iduLicense::checkValid()
{
    SInt                i;
    UInt                sTotal;
    UChar*              sLicense;

    IDE_TEST(mLicense.mHeader != mLicense.mTailer);
    sLicense = (UChar*)&mLicense;

    sTotal = 0;

    for(i = 1; i < (SInt)sizeof(mLicense) - 2; i++)
    {
        sTotal += (UInt)sLicense[i];
    }
    IDE_TEST(mLicense.mCRC != (sTotal % 256));

    return ID_TRUE;

    IDE_EXCEPTION_END;
    return ID_FALSE;
}

IDE_RC iduLicense::applyMax(void)
{
    SChar sCharVal[32];
    SChar sMsg[128];
    ULong sMemMax;
    ULong sDiskMax;

    IDE_TEST(idp::read("MEM_MAX_DB_SIZE", &sMemMax) != IDE_SUCCESS);
    IDE_TEST(idp::read("DISK_MAX_DB_SIZE", &sDiskMax) != IDE_SUCCESS);

    IDE_TEST_RAISE(sMemMax > mMemMax, EMEMMAXEXCEED);

    idlOS::snprintf(sCharVal, sizeof(sCharVal), "%llu", mDiskMax);
    IDE_TEST(idp::updateForce("DISK_MAX_DB_SIZE", sCharVal) != IDE_SUCCESS);
    IDE_TEST(idtCPUSet::relocateCPUs(mMaxCores, mMaxNUMAs) != IDE_SUCCESS);

    return IDE_SUCCESS;

    IDE_EXCEPTION(EMEMMAXEXCEED)
    {
        idlOS::snprintf(sMsg, sizeof(sMsg),
                        "MEM_MAX_DB_SIZE(%llu) exceed license limitation(%llu).\n",
                        sMemMax, mMemMax);
        IDE_CALLBACK_SEND_SYM(sMsg);
    }

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC iduCheckLicense::initializeStatic(void)
{
    return iduLicense::initializeStatic();
}

IDE_RC iduCheckLicense::check()
{
    IDE_TEST(mLicense.load() != IDE_SUCCESS);
    IDE_TEST(mLicense.applyMax() != IDE_SUCCESS);

    return IDE_SUCCESS;

    IDE_EXCEPTION_END;
    return IDE_FAILURE;
}

IDE_RC iduCheckLicense::update()
{
    iduLicense  sLicense;
    SChar       sMsg[128];

    IDE_TEST(sLicense.load() != IDE_SUCCESS);

    IDE_TEST_RAISE(sLicense.mLicense.mType == TRIALEDITION,
                   ECANNOTUPDATETRIAL);
    IDE_TEST_RAISE(
        (sLicense.mLicense.mType == STANDARDEDITION) &&
        (mLicense.mLicense.mType == ENTERPRISEEDITION),
        ECANNOTUPDATESTANDARD);

    IDE_TEST_RAISE(sLicense.mMemMax   < mLicense.mMemMax  , EMEMSMALL);
    IDE_TEST_RAISE(sLicense.mDiskMax  < mLicense.mDiskMax , EDISKSMALL);
    IDE_TEST_RAISE(sLicense.mExpire   < mLicense.mExpire  , EEXPIREPAST);
    IDE_TEST_RAISE(sLicense.mMaxCores < mLicense.mMaxCores, ELESSCORES);
    IDE_TEST_RAISE(sLicense.applyMax() != IDE_SUCCESS     , EAPPLYFAIL);

    if(sLicense.mMaxCores != mLicense.mMaxCores)
    {
        idlOS::snprintf(sMsg, sizeof(sMsg),
                        "Max CPU core count changed from %d to %d.",
                        mLicense.mMaxCores, sLicense.mMaxCores);
        IDE_CALLBACK_SEND_MSG(sMsg);
        IDE_CALLBACK_SEND_MSG("It is recommended to restart the server.");
    }

    idlOS::memcpy(&mLicense, &sLicense, sizeof(iduLicense));

    if(mLicense.mLicense.mType == ENTERPRISEEDITION)
    {
        IDE_CALLBACK_SEND_MSG("MEM_MAX_DB_SIZE can be enlarged to UNLIMITED.");
        IDE_CALLBACK_SEND_MSG("New DISK_MAX_DB_SIZE is UNLIMITED.");
    }
    else
    {
        idlOS::snprintf(sMsg, sizeof(sMsg),
                        "MEM_MAX_DB_SIZE can be enlarged to %lluGB.",
                        mLicense.mMemMax / 1024 / 1024 / 1024);
        IDE_CALLBACK_SEND_MSG(sMsg);
        idlOS::snprintf(sMsg, sizeof(sMsg),
                        "New DISK_MAX_DB_SIZE is %lluGB.",
                        mLicense.mDiskMax / 1024 / 1024 / 1024);
        IDE_CALLBACK_SEND_MSG(sMsg);
    }

    idlOS::snprintf(sMsg, sizeof(sMsg),
                    "New expiry date is %llu.",
                    mLicense.mExpire);
    IDE_CALLBACK_SEND_MSG(sMsg);

    IDE_CALLBACK_SEND_MSG("License update successfully!");

    return IDE_SUCCESS;

    IDE_EXCEPTION(ECANNOTUPDATETRIAL)
    {
        IDE_CALLBACK_SEND_MSG("[ERROR] Cannot update to trial edition.");
    }

    IDE_EXCEPTION(ECANNOTUPDATESTANDARD)
    {
        IDE_CALLBACK_SEND_MSG("[ERROR] Cannot update from enterprise edition "
                              "to standard edition.");
    }

    IDE_EXCEPTION(EMEMSMALL)
    {
        if(mLicense.mMemMax == ID_ULONG_MAX)
        {
            idlOS::snprintf(sMsg, sizeof(sMsg),
                            "[ERROR] New MEM_MAX_DB_SIZE is smaller!\n"
                            "\tCurrent value : UNLIMITED\n"
                            "\tNew value     : %lluGB\n",
                            sLicense.mMemMax / 1024 / 1024 / 1024);
        }
        else
        {
            idlOS::snprintf(sMsg, sizeof(sMsg),
                            "[ERROR] New MEM_MAX_DB_SIZE is smaller!\n"
                            "\tCurrent value : %lluGB\n"
                            "\tNew value     : %lluGB\n",
                            mLicense.mMemMax / 1024 / 1024 / 1024,
                            sLicense.mMemMax / 1024 / 1024 / 1024);
        }
        IDE_CALLBACK_SEND_MSG(sMsg);
    }

    IDE_EXCEPTION(EDISKSMALL)
    {
        if(mLicense.mDiskMax == ID_ULONG_MAX)
        {
            idlOS::snprintf(sMsg, sizeof(sMsg),
                            "[ERROR] New DISK_MAX_DB_SIZE is smaller!\n"
                            "\tCurrent value : UNLIMITED\n"
                            "\tNew value     : %lluGB\n",
                            sLicense.mDiskMax / 1024 / 1024 / 1024);
        }
        else
        {
            idlOS::snprintf(sMsg, sizeof(sMsg),
                            "[ERROR] New DISK_MAX_DB_SIZE is smaller!\n"
                            "\tCurrent value : %lluGB\n"
                            "\tNew value     : %lluGB\n",
                            mLicense.mDiskMax / 1024 / 1024 / 1024,
                            sLicense.mDiskMax / 1024 / 1024 / 1024);
        }
        IDE_CALLBACK_SEND_MSG(sMsg);
    }

    IDE_EXCEPTION(EEXPIREPAST)
    {
        idlOS::snprintf(sMsg, sizeof(sMsg),
                        "[ERROR] New expiry date is improper!\n"
                        "\tCurrent value : %d\n"
                        "\tNew value     : %d\n",
                        mLicense.mExpire,
                        sLicense.mExpire);
        IDE_CALLBACK_SEND_MSG(sMsg);
    }

    IDE_EXCEPTION(ELESSCORES)
    {
        idlOS::snprintf(sMsg, sizeof(sMsg),
                        "[ERROR] New core count is smaller!\n"
                        "\tCurrent value : %llu\n"
                        "\tNew value     : %llu\n",
                        mLicense.mMaxCores,
                        sLicense.mMaxCores);
        IDE_CALLBACK_SEND_MSG(sMsg);
    }

    IDE_EXCEPTION(EAPPLYFAIL)
    {
        IDE_CALLBACK_SEND_MSG("[ERROR] Cannot apply new license!\n");
    }

    IDE_EXCEPTION_END;
    IDE_CALLBACK_SEND_MSG("License update failed!\n");
    return IDE_FAILURE;
}

IDE_RC iduCheckLicense::getHostUniqueString(SChar* aBuf, UInt aBufSize)
{
    idlOS::snprintf(aBuf, aBufSize,
                    "%02X%02X%02X%02X%02X%02X",
                    (UInt)(mLicense.mMacAddr[0].mAddr)[0],
                    (UInt)(mLicense.mMacAddr[0].mAddr)[1],
                    (UInt)(mLicense.mMacAddr[0].mAddr)[2],
                    (UInt)(mLicense.mMacAddr[0].mAddr)[3],
                    (UInt)(mLicense.mMacAddr[0].mAddr)[4],
                    (UInt)(mLicense.mMacAddr[0].mAddr)[5]);

    return IDE_SUCCESS;
}

