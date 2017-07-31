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
#include <ulsdnDbc.h>
#include <ulsdnStmt.h>
#include <ulsdnExecute.h>
#include <ulsdnDescribeCol.h>
#include <ulnConfigFile.h>

#include <sqlcli.h>

#ifndef SQL_API
#define SQL_API
#endif

/*
 * =============================
 * Env Handle
 * =============================
 */
SQLHENV SQLGetEnvHandle(SQLHDBC ConnectionHandle)
{
    ulnDbc *sDbc = NULL;

    ULN_TRACE( SQLGetEnvHandle );

    ACI_TEST( ConnectionHandle == NULL );

    sDbc = (ulnDbc *)ConnectionHandle;

    return (SQLHENV)sDbc->mParentEnv;

    ACI_EXCEPTION_END;

    return NULL;
}

SQLRETURN SQL_API SQLGetParameterCount(SQLHSTMT      aStatementHandle,
                                       SQLUSMALLINT *aParamCount )
{
    acp_uint16_t sParamCount = 0;

    ULN_TRACE( SQLGetParameterCount );

    ACI_TEST( ( aStatementHandle == NULL ) ||
              ( aParamCount      == NULL ) );

    sParamCount = ulnStmtGetParamCount( (ulnStmt*)aStatementHandle );

    *aParamCount = sParamCount;

    return SQL_SUCCESS;

    ACI_EXCEPTION_END;

    return SQL_ERROR;
}

SQLRETURN  SQL_API SQLExecuteForMtDataRows(SQLHSTMT      aStatementHandle,
                                           SQLCHAR      *aOutBuffer,
                                           SQLUINTEGER   aOutBufLength,
                                           SQLPOINTER   *aOffSets,
                                           SQLPOINTER   *aMaxBytes,
                                           SQLUSMALLINT  aColumnCount)
{
    ULN_TRACE( SQLExecuteForMtDataRows );
    ACI_TEST( (aOutBuffer    == NULL) ||
              (aOutBufLength <= 0   ) ||
              (aMaxBytes     == NULL) ||
              (aOffSets      == NULL) );
    return ulsdExecuteForMtDataRows( (ulnStmt     *) aStatementHandle,
                                     (acp_char_t  *) aOutBuffer,
                                     (acp_uint32_t ) aOutBufLength,
                                     (acp_uint32_t*) aOffSets,
                                     (acp_uint32_t*) aMaxBytes,
                                     (acp_uint16_t ) aColumnCount );
    ACI_EXCEPTION_END;
    return SQL_ERROR;
}

void SQL_API SQLGetDbcShardTargetDataNodeName(SQLHDBC     aDbc,
                                              SQLCHAR    *aOutBuff,
                                              SQLINTEGER  aOutBufLength)
{
    acpSnprintf( (acp_char_t *)aOutBuff,
                 aOutBufLength,
                 "%s",
                 ulsdDbcGetShardTargetDataNodeName( (ulnDbc*)aDbc )
               );
}

void SQL_API SQLGetStmtShardTargetDataNodeName(SQLHSTMT    aStmt,
                                               SQLCHAR    *aOutBuff,
                                               SQLINTEGER  aOutBufLength)
{
    acpSnprintf( (acp_char_t *)aOutBuff,
                 aOutBufLength,
                 "%s",
                 ulsdStmtGetShardTargetDataNodeName( (ulnStmt*)aStmt)
               );
}

void SQL_API SQLSetDbcShardTargetDataNodeName(SQLHDBC     aDbc,
                                              SQLCHAR    *aNodeName)
{
    ulsdDbcSetShardTargetDataNodeName( (ulnDbc*)aDbc, aNodeName );
}

void SQL_API SQLSetStmtShardTargetDataNodeName(SQLHSTMT    aStmt,
                                               SQLCHAR    *aNodeName)
{
    ulsdStmtSetShardTargetDataNodeName( (ulnStmt*)aStmt, aNodeName );
}

void SQL_API SQLGetDbcLinkInfo(SQLHDBC     aDbc,
                               SQLCHAR    *aOutBuff,
                               SQLINTEGER  aOutBufLength)
{
    ulsdDbcGetLinkInfo( (ulnDbc      *)aDbc,
                        (acp_char_t  *)aOutBuff,
                        (acp_uint32_t )aOutBufLength );
}

SQLRETURN SQL_API SQLDescribeColEx(SQLHSTMT      StatementHandle,
                                   SQLUSMALLINT  ColumnNumber,
                                   SQLCHAR      *ColumnName,
                                   SQLINTEGER    ColumnNameSize,
                                   SQLUINTEGER  *NameLength,
                                   SQLUINTEGER  *DataMTType,
                                   SQLINTEGER   *Precision,
                                   SQLSMALLINT  *Scale,
                                   SQLSMALLINT  *Nullable)
{
    ULN_TRACE( SQLDescribeCol );

    return ulsdDescribeCol( (ulnStmt      *)StatementHandle,
                            (acp_uint16_t  )ColumnNumber,
                            (acp_char_t   *)ColumnName,
                            (acp_sint32_t  )ColumnNameSize,
                            (acp_uint32_t *)NameLength,
                            (acp_uint32_t *)DataMTType,
                            (acp_sint32_t *)Precision,
                            (acp_sint16_t *)Scale,
                            (acp_sint16_t *)Nullable );
}

