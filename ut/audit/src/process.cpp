/** 
 *  Copyright (c) 1999~2017, Altibase Corp. and/or its affiliates. All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
 
/*******************************************************************************
 * $Id: process.cpp 80540 2017-07-19 08:00:50Z daramix $
 ******************************************************************************/
#include <uto.h>

IDE_RC utScanner::logWritePK(Row * row)
{
    UShort   i;
    Field  * f       = NULL;
    SChar    s[1024] = {0};

    idlOS::fprintf(flog, ":PK->{");

    for(i = 1; i <= mPKCount; i++)
    {
        s[0] = '\0';
        f = row->getField(i);
        IDE_TEST(0 >= f->getSChar(s, sizeof(s)));
        if(i > 1)
        {
            idlOS::fprintf(flog, ",");
        }
        idlOS::fprintf(flog, "%s", s);
    }

    idlOS::fprintf(flog, "}\n");

    ++_fetch;

    return IDE_SUCCESS;

    IDE_EXCEPTION_END;

    return IDE_FAILURE;
}

IDE_RC utScanner::log_diff(ps_t pst)
{
    SChar         values[MAX_DIFF_STR]={'\0'};
    SChar         valuesB[MAX_DIFF_STR]={'\0'};
    SChar         sEllipsis[4] = {'\0'};
    SChar         sEllipsisB[4] = {'\0'};
    const SChar * oop;
    SChar       * ps;
    Field       * f  = NULL;
    Row         * pk = NULL;
    SInt          sSqlType;

    switch(pst)
    {
        case MOSO: oop = "MOSO";
            pk  =  mRowA;
            f  = mRowA->getField(diffColumn.name);
            IDE_TEST(f == NULL);
            sSqlType = f->getRealSqlType();
            /* if sqltype is Lob, value of field is blank */
            if((sSqlType == SQL_BLOB) || (sSqlType == SQL_CLOB))
            {
                strcpy(values, ",");
                break;
            }
            if (f->getSChar(values,MAX_DIFF_STR) == -1)
            {
                idlOS::strcpy(sEllipsis, "...");
            }
            ps = valuesB;
            *ps = ',';
            ps++;
            f  = mRowB->getField(diffColumn.name);
            IDE_TEST(f == NULL);
            if (f->getSChar(ps, MAX_DIFF_STR - 1) == -1)
            {
                idlOS::strcpy(sEllipsisB, "...");
            }
            break;

        case MOSX: oop = "MOSX";
            pk = mRowA;
            f  = mRowA->getField(diffColumn.name);
            IDE_TEST(f == NULL);
            sSqlType = f->getRealSqlType();
            if((sSqlType == SQL_BLOB) || (sSqlType == SQL_CLOB))
            {
                strcpy(values, ",");
            }
            else
            {
                if (f->getSChar(values,MAX_DIFF_STR) == -1)
                {
                    idlOS::strcpy(sEllipsis, "...");
                }
            }
            break;

        case MXSO: oop = "MXSO";
            pk = mRowB;
            f  = mRowB->getField(diffColumn.name);
            IDE_TEST(f == NULL);
            sSqlType = f->getRealSqlType();
            if((sSqlType == SQL_BLOB) || (sSqlType == SQL_CLOB))
            {
                strcpy(values, ",");
            }
            else
            {
                if (f->getSChar(values,MAX_DIFF_STR) == -1)
                {
                    idlOS::strcpy(sEllipsis, "...");
                }
            }
            break;

        default:
            return IDE_SUCCESS;
    }

    idlOS::fprintf(flog, "%s[%d,%d]->%s(%s%s%s%s)",
                         oop,
                         mSelectA->rows(),
                         mSelectB->rows(),
                         diffColumn.name,
                         values,
                         sEllipsis,
                         valuesB,
                         sEllipsisB);

    return logWritePK(pk);

    IDE_EXCEPTION_END;

    return IDE_FAILURE;
}
