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

#include <uln.h>
#include <ulnPrivate.h>
#include <ulnConv.h>
#include <ulnConvToTIMESTAMP.h>

ACI_RC ulncCHAR_TIMESTAMP(ulnFnContext  *aFnContext,
                          ulnAppBuffer  *aAppBuffer,
                          ulnColumn     *aColumn,
                          ulnLengthPair *aLength,
                          acp_uint16_t   aRowNumber)
{
    acp_char_t           *sDateFormat;
    acp_char_t           *sDateString;

    mtdDateType           sMtdDate = mtcdDateNull;       //BUG-28561 [CodeSonar] Uninitialized Variable
    SQL_TIMESTAMP_STRUCT *sUserDate;

    acp_uint8_t           sErrMsgBuf[32] = {'\0', };

    sUserDate   = (SQL_TIMESTAMP_STRUCT *)aAppBuffer->mBuffer;
    sDateString = (acp_char_t *)aColumn->mBuffer;

    sDateFormat = aFnContext->mHandle.mStmt->mParentDbc->mDateFormat;

    ACI_TEST_RAISE( mtdDateInterfaceToDate(&sMtdDate,
                                           (acp_uint8_t *)sDateString,
                                           aColumn->mDataLength,
                                           (acp_uint8_t *)sDateFormat,
                                           acpCStrLen(sDateFormat, ACP_SINT32_MAX))
                    != ACI_SUCCESS, INVALID_DATE_STR_ERROR );

    sUserDate->year     = mtdDateInterfaceYear(&sMtdDate);
    sUserDate->month    = mtdDateInterfaceMonth(&sMtdDate);
    sUserDate->day      = mtdDateInterfaceDay(&sMtdDate);
    sUserDate->hour     = mtdDateInterfaceHour(&sMtdDate);
    sUserDate->minute   = mtdDateInterfaceMinute(&sMtdDate);
    sUserDate->second   = mtdDateInterfaceSecond(&sMtdDate);
    sUserDate->fraction = mtdDateInterfaceMicroSecond(&sMtdDate) * 1000; /* to nano-sec */

#if 0
    /*
     * BUGBUG : 이거, invalid date format 이 나와버리는 상황에서
     *          fractional truc 를 줘야 한다고 ODBC 는 말한다. 
     *          지금은
     *          에라 모르겠다. 그냥 무조건 성공 -_-;
     */
    if (mtdDateInterfaceMicroSecond(&sMtdDate) != 0)
    {
        /*
         * 01s07 
         *
         * BUGBUG : fraction portion 이 0 인지까지 체크해야 하나?
         *
         * Altibase 의 DATE 타입은 사실상 SQL_TIMESTAMP 타입이다.
         * SQL_TIMESTAMP --> SQL_DATE 변환시에
         *      1. timestamp 의 date 부분은 무시된다.
         *      2. timestamp 의 time 부분이 0 이 아니면, 01S07 리턴한다.
         */
        ulnErrorExtended(aFnContext,
                         aRowNumber,
                         aColumn->mColumnNumber,
                         ulERR_IGNORE_FRACTIONAL_TRUNCATION);
    }
#endif

    aLength->mNeeded  = ACI_SIZEOF(SQL_TIMESTAMP_STRUCT);
    aLength->mWritten = ACI_SIZEOF(SQL_TIMESTAMP_STRUCT);

    return ACI_SUCCESS;

    ACI_EXCEPTION( INVALID_DATE_STR_ERROR )
    {
        acpMemCpy( sErrMsgBuf,
                   sDateString,
                   ACP_MIN(31, aColumn->mDataLength) );
        ulnErrorExtended( aFnContext,
                          aRowNumber,
                          aColumn->mColumnNumber,
                          ulERR_ABORT_INVALID_DATE_STRING,
                          sErrMsgBuf,
                          sDateFormat );
    }
    ACI_EXCEPTION_END;

    return ACI_FAILURE;
}

ACI_RC ulncVARCHAR_TIMESTAMP(ulnFnContext  *aFnContext,
                             ulnAppBuffer  *aAppBuffer,
                             ulnColumn     *aColumn,
                             ulnLengthPair *aLength,
                             acp_uint16_t   aRowNumber)
{
    return ulncCHAR_TIMESTAMP(aFnContext,
                              aAppBuffer,
                              aColumn,
                              aLength,
                              aRowNumber);
}

ACI_RC ulncDATE_TIMESTAMP(ulnFnContext  *aFnContext,
                          ulnAppBuffer  *aAppBuffer,
                          ulnColumn     *aColumn,
                          ulnLengthPair *aLength,
                          acp_uint16_t   aRowNumber)
{
    mtdDateType          *sMtdDate;
    SQL_TIMESTAMP_STRUCT *sUserDate;

    ACP_UNUSED(aFnContext);
    ACP_UNUSED(aRowNumber);

    sMtdDate  = (mtdDateType *)aColumn->mBuffer;
    sUserDate = (SQL_TIMESTAMP_STRUCT *)aAppBuffer->mBuffer;

    sUserDate->year     = mtdDateInterfaceYear(sMtdDate);
    sUserDate->month    = mtdDateInterfaceMonth(sMtdDate);
    sUserDate->day      = mtdDateInterfaceDay(sMtdDate);
    sUserDate->hour     = mtdDateInterfaceHour(sMtdDate);
    sUserDate->minute   = mtdDateInterfaceMinute(sMtdDate);
    sUserDate->second   = mtdDateInterfaceSecond(sMtdDate);
    sUserDate->fraction = mtdDateInterfaceMicroSecond(sMtdDate) * 1000; /* to nano-sec */

    aLength->mWritten = ACI_SIZEOF(SQL_TIMESTAMP_STRUCT);
    aLength->mNeeded  = ACI_SIZEOF(SQL_TIMESTAMP_STRUCT);

    return ACI_SUCCESS;
}

ACI_RC ulncINTERVAL_TIMESTAMP(ulnFnContext  *aFnContext,
                              ulnAppBuffer  *aAppBuffer,
                              ulnColumn     *aColumn,
                              ulnLengthPair *aLength,
                              acp_uint16_t   aRowNumber)
{
    ACP_UNUSED(aAppBuffer);
    ACP_UNUSED(aLength);

    /*
     * 07006
     */
    return ulnErrorExtended(aFnContext,
                            aRowNumber,
                            aColumn->mColumnNumber,
                            ulERR_ABORT_INVALID_CONVERSION);
}

ACI_RC ulncNCHAR_TIMESTAMP(ulnFnContext  *aFnContext,
                           ulnAppBuffer  *aAppBuffer,
                           ulnColumn     *aColumn,
                           ulnLengthPair *aLength,
                           acp_uint16_t   aRowNumber)
{
    acp_char_t           *sDateFormat;

    mtdDateType           sMtdDate = mtcdDateNull;       //BUG-28561 [CodeSonar] Uninitialized Variable
    SQL_TIMESTAMP_STRUCT *sUserDate;

    ulnDbc               *sDbc;
    ulnCharSet            sCharSet;
    acp_sint32_t          sState = 0;

    acp_uint8_t           sErrMsgBuf[32] = {'\0', };

    ulnCharSetInitialize(&sCharSet);
    sState = 1;

    ULN_FNCONTEXT_GET_DBC(aFnContext, sDbc);

    ACI_TEST( sDbc == NULL );     //BUG-28561 [CodeSonar] Null Pointer Dereference

    ACI_TEST(ulnCharSetConvert(&sCharSet,
                               aFnContext,
                               NULL,
                               (const mtlModule*)sDbc->mNcharCharsetLangModule,
                               sDbc->mClientCharsetLangModule,    //BUG-22684
                               (void*)aColumn->mBuffer,
                               aColumn->mDataLength,
                               CONV_DATA_OUT)
             != ACI_SUCCESS);

    sUserDate   = (SQL_TIMESTAMP_STRUCT *)aAppBuffer->mBuffer;

    sDateFormat = aFnContext->mHandle.mStmt->mParentDbc->mDateFormat;

    ACI_TEST_RAISE( mtdDateInterfaceToDate(&sMtdDate,
                                           ulnCharSetGetConvertedText(&sCharSet),
                                           ulnCharSetGetConvertedTextLen(&sCharSet),
                                           (acp_uint8_t *)sDateFormat,
                                           acpCStrLen(sDateFormat, ACP_SINT32_MAX))
                    != ACI_SUCCESS, INVALID_DATE_STR_ERROR );

    sUserDate->year     = mtdDateInterfaceYear(&sMtdDate);
    sUserDate->month    = mtdDateInterfaceMonth(&sMtdDate);
    sUserDate->day      = mtdDateInterfaceDay(&sMtdDate);
    sUserDate->hour     = mtdDateInterfaceHour(&sMtdDate);
    sUserDate->minute   = mtdDateInterfaceMinute(&sMtdDate);
    sUserDate->second   = mtdDateInterfaceSecond(&sMtdDate);
    sUserDate->fraction = mtdDateInterfaceMicroSecond(&sMtdDate) * 1000; /* to nano-sec */

#if 0
    /*
     * BUGBUG : 이거, invalid date format 이 나와버리는 상황에서
     *          fractional truc 를 줘야 한다고 ODBC 는 말한다. 
     *          지금은
     *          에라 모르겠다. 그냥 무조건 성공 -_-;
     */
    if (mtdDateInterfaceMicroSecond(&sMtdDate) != 0)
    {
        /*
         * 01s07
         *
         * BUGBUG : fraction portion 이 0 인지까지 체크해야 하나?
         *
         * Altibase 의 DATE 타입은 사실상 SQL_TIMESTAMP 타입이다.
         * SQL_TIMESTAMP --> SQL_DATE 변환시에
         *      1. timestamp 의 date 부분은 무시된다.
         *      2. timestamp 의 time 부분이 0 이 아니면, 01S07 리턴한다.
         */
        ulnErrorExtended(aFnContext,
                         aRowNumber,
                         aColumn->mColumnNumber,
                         ulERR_IGNORE_FRACTIONAL_TRUNCATION);
    }
#endif

    aLength->mNeeded  = ACI_SIZEOF(SQL_TIMESTAMP_STRUCT);
    aLength->mWritten = ACI_SIZEOF(SQL_TIMESTAMP_STRUCT);

    sState = 0;
    ulnCharSetFinalize(&sCharSet);

    return ACI_SUCCESS;

    ACI_EXCEPTION( INVALID_DATE_STR_ERROR )
    {
        acpMemCpy( sErrMsgBuf,
                   ulnCharSetGetConvertedText(&sCharSet),
                   ACP_MIN(31, ulnCharSetGetConvertedTextLen(&sCharSet)) );
        ulnErrorExtended( aFnContext,
                          aRowNumber,
                          aColumn->mColumnNumber,
                          ulERR_ABORT_INVALID_DATE_STRING,
                          sErrMsgBuf,
                          sDateFormat );
    }
    ACI_EXCEPTION_END;

    if (sState == 1)
    {
        ulnCharSetFinalize(&sCharSet);
    }

    return ACI_FAILURE;
}

ACI_RC ulncNVARCHAR_TIMESTAMP(ulnFnContext  *aFnContext,
                              ulnAppBuffer  *aAppBuffer,
                              ulnColumn     *aColumn,
                              ulnLengthPair *aLength,
                              acp_uint16_t   aRowNumber)
{
    return ulncCHAR_TIMESTAMP(aFnContext,
                              aAppBuffer,
                              aColumn,
                              aLength,
                              aRowNumber);
}
