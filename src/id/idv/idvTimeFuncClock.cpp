/***********************************************************************
 * Copyright 1999-2000, RTBase Corporation or its subsidiaries.
 * All rights reserved.
 **********************************************************************/

/***********************************************************************
 * $Id: idvTimeFuncClock.cpp 26440 2008-06-10 04:02:48Z jdlee $
 **********************************************************************/

#include <idl.h>
#include <ide.h>
#include <idv.h>
#include <idp.h>
#include <idu.h>
#include <idv.h>

/* ------------------------------------------------
 * Clock Tick
 * ----------------------------------------------*/

static void   gClockInit(idvTime *aValue)
{
    aValue->iTime.mClock = 0;
}

static idBool gClockIsInit(idvTime *aValue)
{
    return (aValue->iTime.mClock == 0) ? ID_TRUE : ID_FALSE;
}

static void   gClockGet(idvTime *aValue)
{
    aValue->iTime.mClock = idvGetClockTickFromSystem();
}

// call by callback. convert to micro second.
static ULong  gClockDiff(idvTime *aBefore, idvTime *aAfter)
{
    return (aAfter->iTime.mClock - aBefore->iTime.mClock) / idvManager::getClock();
}

static ULong  gClockMicro(idvTime *aValue)
{
    return (aValue->iTime.mClock / idvManager::getClock());
}

static idBool gClockIsOlder(idvTime *aBefore, idvTime *aAfter)
{
    return ( gClockMicro(aBefore)> gClockMicro(aAfter)) ? ID_TRUE : ID_FALSE;
}


idvTimeFunc gClockFunctions =
{
    gClockInit,
    gClockIsInit,
    gClockGet,
    gClockDiff,
    gClockMicro,
    gClockIsOlder
};

