
/* A Bison parser, made by GNU Bison 2.4.1.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
   
      Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.4.1"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse         COMPparse
#define yylex           COMPlex
#define yyerror         COMPerror
#define yylval          COMPlval
#define yychar          COMPchar
#define yydebug         COMPdebug
#define yynerrs         COMPnerrs


/* Copy the first part of user declarations.  */

/* Line 189 of yacc.c  */
#line 3 "ulpCompy.y"

#include <ulpComp.h>
#include <sqlcli.h>


/* Line 189 of yacc.c  */
#line 87 "ulpCompy.cpp"

/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     END_OF_FILE = 258,
     C_AUTO = 259,
     C_BREAK = 260,
     C_CASE = 261,
     C_CHAR = 262,
     C_VARCHAR = 263,
     C_CONST = 264,
     C_CONTINUE = 265,
     C_DEFAULT = 266,
     C_DO = 267,
     C_DOUBLE = 268,
     C_ENUM = 269,
     C_EXTERN = 270,
     C_FLOAT = 271,
     C_FOR = 272,
     C_GOTO = 273,
     C_INT = 274,
     C_LONG = 275,
     C_REGISTER = 276,
     C_RETURN = 277,
     C_SHORT = 278,
     C_SIGNED = 279,
     C_SIZEOF = 280,
     C_STATIC = 281,
     C_STRUCT = 282,
     C_SWITCH = 283,
     C_TYPEDEF = 284,
     C_UNION = 285,
     C_UNSIGNED = 286,
     C_VOID = 287,
     C_VOLATILE = 288,
     C_WHILE = 289,
     C_ELIPSIS = 290,
     C_ELSE = 291,
     C_IF = 292,
     C_CONSTANT = 293,
     C_IDENTIFIER = 294,
     C_TYPE_NAME = 295,
     C_STRING_LITERAL = 296,
     C_RIGHT_ASSIGN = 297,
     C_LEFT_ASSIGN = 298,
     C_ADD_ASSIGN = 299,
     C_SUB_ASSIGN = 300,
     C_MUL_ASSIGN = 301,
     C_DIV_ASSIGN = 302,
     C_MOD_ASSIGN = 303,
     C_AND_ASSIGN = 304,
     C_XOR_ASSIGN = 305,
     C_OR_ASSIGN = 306,
     C_INC_OP = 307,
     C_DEC_OP = 308,
     C_PTR_OP = 309,
     C_AND_OP = 310,
     C_EQ_OP = 311,
     C_NE_OP = 312,
     C_RIGHT_OP = 313,
     C_LEFT_OP = 314,
     C_OR_OP = 315,
     C_LE_OP = 316,
     C_GE_OP = 317,
     C_APRE_BINARY = 318,
     C_APRE_BIT = 319,
     C_APRE_BYTES = 320,
     C_APRE_VARBYTES = 321,
     C_APRE_NIBBLE = 322,
     C_APRE_INTEGER = 323,
     C_APRE_NUMERIC = 324,
     C_APRE_BLOB_LOCATOR = 325,
     C_APRE_CLOB_LOCATOR = 326,
     C_APRE_BLOB = 327,
     C_APRE_CLOB = 328,
     C_SQLLEN = 329,
     C_SQL_TIMESTAMP_STRUCT = 330,
     C_SQL_TIME_STRUCT = 331,
     C_SQL_DATE_STRUCT = 332,
     C_SQL_DA_STRUCT = 333,
     C_FAILOVERCB = 334,
     C_NCHAR_CS = 335,
     C_ATTRIBUTE = 336,
     M_INCLUDE = 337,
     M_DEFINE = 338,
     M_UNDEF = 339,
     M_FUNCTION = 340,
     M_LBRAC = 341,
     M_RBRAC = 342,
     M_DQUOTE = 343,
     M_FILENAME = 344,
     M_IF = 345,
     M_ELIF = 346,
     M_ELSE = 347,
     M_ENDIF = 348,
     M_IFDEF = 349,
     M_IFNDEF = 350,
     M_CONSTANT = 351,
     M_IDENTIFIER = 352,
     EM_SQLSTART = 353,
     EM_ERROR = 354,
     TR_ADD = 355,
     TR_AFTER = 356,
     TR_AGER = 357,
     TR_ALL = 358,
     TR_ALTER = 359,
     TR_AND = 360,
     TR_ANY = 361,
     TR_ARCHIVE = 362,
     TR_ARCHIVELOG = 363,
     TR_AS = 364,
     TR_ASC = 365,
     TR_AT = 366,
     TR_BACKUP = 367,
     TR_BEFORE = 368,
     TR_BEGIN = 369,
     TR_BY = 370,
     TR_BIND = 371,
     TR_CASCADE = 372,
     TR_CASE = 373,
     TR_CAST = 374,
     TR_CHECK_OPENING_PARENTHESIS = 375,
     TR_CLOSE = 376,
     TR_COALESCE = 377,
     TR_COLUMN = 378,
     TR_COMMENT = 379,
     TR_COMMIT = 380,
     TR_COMPILE = 381,
     TR_CONNECT = 382,
     TR_CONSTRAINT = 383,
     TR_CONSTRAINTS = 384,
     TR_CONTINUE = 385,
     TR_CREATE = 386,
     TR_VOLATILE = 387,
     TR_CURSOR = 388,
     TR_CYCLE = 389,
     TR_DATABASE = 390,
     TR_DECLARE = 391,
     TR_DEFAULT = 392,
     TR_DELETE = 393,
     TR_DEQUEUE = 394,
     TR_DESC = 395,
     TR_DIRECTORY = 396,
     TR_DISABLE = 397,
     TR_DISCONNECT = 398,
     TR_DISTINCT = 399,
     TR_DROP = 400,
     TR_DESCRIBE = 401,
     TR_DESCRIPTOR = 402,
     TR_EACH = 403,
     TR_ELSE = 404,
     TR_ELSEIF = 405,
     TR_ENABLE = 406,
     TR_END = 407,
     TR_ENQUEUE = 408,
     TR_ESCAPE = 409,
     TR_EXCEPTION = 410,
     TR_EXEC = 411,
     TR_EXECUTE = 412,
     TR_EXIT = 413,
     TR_FAILOVERCB = 414,
     TR_FALSE = 415,
     TR_FETCH = 416,
     TR_FIFO = 417,
     TR_FLUSH = 418,
     TR_FOR = 419,
     TR_FOREIGN = 420,
     TR_FROM = 421,
     TR_FULL = 422,
     TR_FUNCTION = 423,
     TR_GOTO = 424,
     TR_GRANT = 425,
     TR_GROUP = 426,
     TR_HAVING = 427,
     TR_IF = 428,
     TR_IN = 429,
     TR_IN_BF_LPAREN = 430,
     TR_INNER = 431,
     TR_INSERT = 432,
     TR_INTERSECT = 433,
     TR_INTO = 434,
     TR_IS = 435,
     TR_ISOLATION = 436,
     TR_JOIN = 437,
     TR_KEY = 438,
     TR_LEFT = 439,
     TR_LESS = 440,
     TR_LEVEL = 441,
     TR_LIFO = 442,
     TR_LIKE = 443,
     TR_LIMIT = 444,
     TR_LOCAL = 445,
     TR_LOGANCHOR = 446,
     TR_LOOP = 447,
     TR_MERGE = 448,
     TR_MOVE = 449,
     TR_MOVEMENT = 450,
     TR_NEW = 451,
     TR_NOARCHIVELOG = 452,
     TR_NOCYCLE = 453,
     TR_NOT = 454,
     TR_NULL = 455,
     TR_OF = 456,
     TR_OFF = 457,
     TR_OLD = 458,
     TR_ON = 459,
     TR_OPEN = 460,
     TR_OR = 461,
     TR_ORDER = 462,
     TR_OUT = 463,
     TR_OUTER = 464,
     TR_OVER = 465,
     TR_PARTITION = 466,
     TR_PARTITIONS = 467,
     TR_POINTER = 468,
     TR_PRIMARY = 469,
     TR_PRIOR = 470,
     TR_PRIVILEGES = 471,
     TR_PROCEDURE = 472,
     TR_PUBLIC = 473,
     TR_QUEUE = 474,
     TR_READ = 475,
     TR_REBUILD = 476,
     TR_RECOVER = 477,
     TR_REFERENCES = 478,
     TR_REFERENCING = 479,
     TR_REGISTER = 480,
     TR_RESTRICT = 481,
     TR_RETURN = 482,
     TR_REVOKE = 483,
     TR_RIGHT = 484,
     TR_ROLLBACK = 485,
     TR_ROW = 486,
     TR_SAVEPOINT = 487,
     TR_SELECT = 488,
     TR_SEQUENCE = 489,
     TR_SESSION = 490,
     TR_SET = 491,
     TR_SOME = 492,
     TR_SPLIT = 493,
     TR_START = 494,
     TR_STATEMENT = 495,
     TR_SYNONYM = 496,
     TR_TABLE = 497,
     TR_TEMPORARY = 498,
     TR_THAN = 499,
     TR_THEN = 500,
     TR_TO = 501,
     TR_TRIGGER = 502,
     TR_TRUE = 503,
     TR_TYPE = 504,
     TR_TYPESET = 505,
     TR_UNION = 506,
     TR_UNIQUE = 507,
     TR_UNREGISTER = 508,
     TR_UNTIL = 509,
     TR_UPDATE = 510,
     TR_USER = 511,
     TR_USING = 512,
     TR_VALUES = 513,
     TR_VARIABLE = 514,
     TR_VARIABLES = 515,
     TR_VIEW = 516,
     TR_WHEN = 517,
     TR_WHERE = 518,
     TR_WHILE = 519,
     TR_WITH = 520,
     TR_WORK = 521,
     TR_WRITE = 522,
     TR_PARALLEL = 523,
     TR_NOPARALLEL = 524,
     TR_LOB = 525,
     TR_STORE = 526,
     TR_ENDEXEC = 527,
     TR_PRECEDING = 528,
     TR_FOLLOWING = 529,
     TR_CURRENT_ROW = 530,
     TR_LINK = 531,
     TR_ROLE = 532,
     TR_WITHIN = 533,
     TK_BETWEEN = 534,
     TK_EXISTS = 535,
     TO_ACCESS = 536,
     TO_CONSTANT = 537,
     TO_IDENTIFIED = 538,
     TO_INDEX = 539,
     TO_MINUS = 540,
     TO_MODE = 541,
     TO_OTHERS = 542,
     TO_RAISE = 543,
     TO_RENAME = 544,
     TO_REPLACE = 545,
     TO_ROWTYPE = 546,
     TO_SEGMENT = 547,
     TO_WAIT = 548,
     TO_PIVOT = 549,
     TO_UNPIVOT = 550,
     TO_MATERIALIZED = 551,
     TO_CONNECT_BY_NOCYCLE = 552,
     TO_CONNECT_BY_ROOT = 553,
     TO_NULLS = 554,
     TO_PURGE = 555,
     TO_FLASHBACK = 556,
     TO_VC2COLL = 557,
     TA_ELSIF = 558,
     TA_EXTENTSIZE = 559,
     TA_FIXED = 560,
     TA_LOCK = 561,
     TA_MAXROWS = 562,
     TA_ONLINE = 563,
     TA_OFFLINE = 564,
     TA_REPLICATION = 565,
     TA_REVERSE = 566,
     TA_ROWCOUNT = 567,
     TA_STEP = 568,
     TA_TABLESPACE = 569,
     TA_TRUNCATE = 570,
     TA_SQLCODE = 571,
     TA_SQLERRM = 572,
     TA_LINKER = 573,
     TA_REMOTE_TABLE = 574,
     TA_SHARD = 575,
     TA_DISJOIN = 576,
     TA_CONJOIN = 577,
     TI_NONQUOTED_IDENTIFIER = 578,
     TI_QUOTED_IDENTIFIER = 579,
     TI_HOSTVARIABLE = 580,
     TL_TYPED_LITERAL = 581,
     TL_LITERAL = 582,
     TL_NCHAR_LITERAL = 583,
     TL_UNICODE_LITERAL = 584,
     TL_INTEGER = 585,
     TL_NUMERIC = 586,
     TS_AT_SIGN = 587,
     TS_CONCATENATION_SIGN = 588,
     TS_DOUBLE_PERIOD = 589,
     TS_EXCLAMATION_POINT = 590,
     TS_PERCENT_SIGN = 591,
     TS_OPENING_PARENTHESIS = 592,
     TS_CLOSING_PARENTHESIS = 593,
     TS_OPENING_BRACKET = 594,
     TS_CLOSING_BRACKET = 595,
     TS_ASTERISK = 596,
     TS_PLUS_SIGN = 597,
     TS_COMMA = 598,
     TS_MINUS_SIGN = 599,
     TS_PERIOD = 600,
     TS_SLASH = 601,
     TS_COLON = 602,
     TS_SEMICOLON = 603,
     TS_LESS_THAN_SIGN = 604,
     TS_EQUAL_SIGN = 605,
     TS_GREATER_THAN_SIGN = 606,
     TS_QUESTION_MARK = 607,
     TS_OUTER_JOIN_OPERATOR = 608,
     TX_HINTS = 609,
     SES_V_NUMERIC = 610,
     SES_V_INTEGER = 611,
     SES_V_HOSTVARIABLE = 612,
     SES_V_LITERAL = 613,
     SES_V_TYPED_LITERAL = 614,
     SES_V_DQUOTE_LITERAL = 615,
     SES_V_IDENTIFIER = 616,
     SES_V_ABSOLUTE = 617,
     SES_V_ALLOCATE = 618,
     SES_V_ASENSITIVE = 619,
     SES_V_AUTOCOMMIT = 620,
     SES_V_BATCH = 621,
     SES_V_BLOB_FILE = 622,
     SES_V_BREAK = 623,
     SES_V_CLOB_FILE = 624,
     SES_V_CUBE = 625,
     SES_V_DEALLOCATE = 626,
     SES_V_DESCRIPTOR = 627,
     SES_V_DO = 628,
     SES_V_FIRST = 629,
     SES_V_FOUND = 630,
     SES_V_FREE = 631,
     SES_V_HOLD = 632,
     SES_V_IMMEDIATE = 633,
     SES_V_INDICATOR = 634,
     SES_V_INSENSITIVE = 635,
     SES_V_LAST = 636,
     SES_V_NEXT = 637,
     SES_V_ONERR = 638,
     SES_V_ONLY = 639,
     APRE_V_OPTION = 640,
     SES_V_PREPARE = 641,
     SES_V_RELATIVE = 642,
     SES_V_RELEASE = 643,
     SES_V_ROLLUP = 644,
     SES_V_SCROLL = 645,
     SES_V_SENSITIVE = 646,
     SES_V_SQLERROR = 647,
     SES_V_THREADS = 648,
     SES_V_WHENEVER = 649,
     SES_V_CURRENT = 650,
     SES_V_GROUPING_SETS = 651
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 214 of yacc.c  */
#line 8 "ulpCompy.y"

    char *strval;



/* Line 214 of yacc.c  */
#line 525 "ulpCompy.cpp"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif


/* Copy the second part of user declarations.  */

/* Line 264 of yacc.c  */
#line 37 "ulpCompy.y"


#undef YY_READ_BUF_SIZE
#undef YY_BUF_SIZE
#define YY_READ_BUF_SIZE (16384)
#define YY_BUF_SIZE (YY_READ_BUF_SIZE * 2) /* size of default input buffer */

//============== global variables for COMPparse ================//

/* externs of ulpMain.h */
extern ulpProgOption gUlpProgOption;
extern ulpCodeGen    gUlpCodeGen;
extern iduMemory    *gUlpMem;

// Macro table
extern ulpMacroTable  gUlpMacroT;
// Scope table
extern ulpScopeTable  gUlpScopeT;
// Struct tabletable
extern ulpStructTable gUlpStructT;

/* externs of COMPLexer */
extern idBool         gDontPrint2file;
extern SInt           gUlpCOMPMacroExpIndex;
/* BUG-31831 : An additional error message is needed to notify 
the unacceptability of using varchar type in #include file.
include file 파싱중인지를 알려줌 */
extern SInt           gUlpCOMPIncludeIndex;

/* extern of PPIF parser */
extern SChar         *gUlpPPIFbufptr;
extern SChar         *gUlpPPIFbuflim;

// lexer의 시작상태를 지정함.
SInt                 gUlpCOMPStartCond = CP_ST_NONE;
/* 이전 상태로 복귀하기 위한 변수 */
SInt                 gUlpCOMPPrevCond  = CP_ST_NONE;

/* BUG-35518 Shared pointer should be supported in APRE */
SInt                 gUlpSharedPtrPrevCond  = CP_ST_NONE;

// parsing중에 상태 정보 & C 변수에 대한 정보 저장.
ulpParseInfo         gUlpParseInfo;

// 현제 scope depth
SInt                 gUlpCurDepth = 0;

// 현재 처리중인 stmt type
ulpStmtType          gUlpStmttype    = S_UNKNOWN;
// sql query string 을 저장해야하는지 여부. 
idBool               gUlpIsPrintStmt = ID_TRUE;

// 현재 처리중인 host변수의 indicator 정보
ulpSymTElement      *gUlpIndNode = NULL;
SChar                gUlpIndName[MAX_HOSTVAR_NAME_SIZE * 2];
// 현재 처리중인 host변수의 file option 변수 정보
SChar                gUlpFileOptName[MAX_HOSTVAR_NAME_SIZE * 2];

/* macro if 조건문처리를 위한 변수들. */
ulpPPifstackMgr     *gUlpCOMPifstackMgr[MAX_HEADER_FILE_NUM];
SInt                 gUlpCOMPifstackInd = -1;

extern SChar        *gUlpCOMPErrCode;

//============================================================//


//=========== Function declarations for COMPparse ============//

// Macro if 구문 처리를 위한 parse 함수
extern SInt PPIFparse ( void *aBuf, SInt *aRes );
extern int  COMPlex   ( YYSTYPE *lvalp );
extern void COMPerror ( const SChar* aMsg );

extern void ulpFinalizeError(void);

//============================================================//

/* BUG-42357 */
extern int COMPlineno;



/* Line 264 of yacc.c  */
#line 621 "ulpCompy.cpp"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static int
YYID (int yyi)
#else
static int
YYID (yyi)
    int yyi;
#endif
{
  return yyi;
}
#endif

#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined _STDLIB_H \
       && ! ((defined YYMALLOC || defined malloc) \
	     && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
	 || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)		\
      do					\
	{					\
	  YYSIZE_T yyi;				\
	  for (yyi = 0; yyi < (Count); yyi++)	\
	    (To)[yyi] = (From)[yyi];		\
	}					\
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)				\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	YYCOPY (&yyptr->Stack_alloc, Stack, yysize);			\
	Stack = &yyptr->Stack_alloc;					\
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  105
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   14906

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  421
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  699
/* YYNRULES -- Number of rules.  */
#define YYNRULES  1945
/* YYNRULES -- Number of states.  */
#define YYNSTATES  3712

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   651

#define YYTRANSLATE(YYX)						\
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint16 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   408,     2,     2,     2,   410,   403,     2,
     397,   398,   404,   405,   402,   406,   401,   409,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,   416,   418,
     411,   417,   412,   415,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,   399,     2,   400,   413,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,   420,   414,   419,   407,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51,    52,    53,    54,
      55,    56,    57,    58,    59,    60,    61,    62,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    80,    81,    82,    83,    84,
      85,    86,    87,    88,    89,    90,    91,    92,    93,    94,
      95,    96,    97,    98,    99,   100,   101,   102,   103,   104,
     105,   106,   107,   108,   109,   110,   111,   112,   113,   114,
     115,   116,   117,   118,   119,   120,   121,   122,   123,   124,
     125,   126,   127,   128,   129,   130,   131,   132,   133,   134,
     135,   136,   137,   138,   139,   140,   141,   142,   143,   144,
     145,   146,   147,   148,   149,   150,   151,   152,   153,   154,
     155,   156,   157,   158,   159,   160,   161,   162,   163,   164,
     165,   166,   167,   168,   169,   170,   171,   172,   173,   174,
     175,   176,   177,   178,   179,   180,   181,   182,   183,   184,
     185,   186,   187,   188,   189,   190,   191,   192,   193,   194,
     195,   196,   197,   198,   199,   200,   201,   202,   203,   204,
     205,   206,   207,   208,   209,   210,   211,   212,   213,   214,
     215,   216,   217,   218,   219,   220,   221,   222,   223,   224,
     225,   226,   227,   228,   229,   230,   231,   232,   233,   234,
     235,   236,   237,   238,   239,   240,   241,   242,   243,   244,
     245,   246,   247,   248,   249,   250,   251,   252,   253,   254,
     255,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
   YYRHS.  */
static const yytype_uint16 yyprhs[] =
{
       0,     0,     3,     5,     8,    10,    12,    14,    16,    18,
      20,    22,    24,    26,    30,    32,    37,    41,    46,    50,
      54,    57,    60,    62,    66,    68,    71,    74,    77,    80,
      85,    87,    89,    91,    93,    95,    97,    99,   104,   106,
     110,   114,   118,   120,   124,   128,   130,   134,   138,   140,
     144,   148,   152,   156,   158,   162,   166,   168,   172,   174,
     178,   180,   184,   186,   190,   192,   196,   198,   204,   206,
     210,   212,   214,   216,   218,   220,   222,   224,   226,   228,
     230,   232,   234,   238,   240,   243,   247,   249,   252,   254,
     257,   259,   263,   265,   267,   271,   273,   275,   277,   279,
     281,   283,   285,   288,   291,   293,   295,   297,   299,   301,
     303,   305,   307,   309,   311,   313,   315,   317,   319,   321,
     323,   325,   327,   329,   331,   333,   335,   337,   339,   341,
     343,   345,   347,   349,   351,   352,   354,   359,   365,   370,
     376,   379,   382,   384,   386,   388,   390,   393,   395,   397,
     401,   402,   404,   408,   410,   412,   415,   419,   424,   430,
     433,   435,   439,   441,   445,   447,   450,   452,   456,   460,
     465,   469,   474,   479,   481,   483,   485,   488,   491,   495,
     497,   500,   502,   506,   508,   512,   514,   518,   520,   524,
     527,   529,   531,   534,   536,   538,   541,   545,   548,   552,
     556,   561,   564,   568,   572,   577,   579,   583,   588,   590,
     594,   596,   598,   600,   602,   604,   606,   610,   614,   619,
     623,   628,   632,   635,   639,   641,   643,   645,   647,   650,
     652,   654,   657,   659,   662,   668,   676,   682,   688,   696,
     703,   711,   719,   728,   736,   745,   754,   764,   768,   771,
     774,   777,   781,   784,   788,   790,   793,   795,   797,   800,
     802,   804,   806,   808,   810,   812,   814,   816,   818,   823,
     828,   831,   834,   837,   839,   841,   844,   847,   849,   851,
     856,   861,   866,   872,   877,   881,   885,   889,   892,   893,
     896,   899,   901,   903,   905,   907,   909,   911,   913,   915,
     917,   921,   925,   933,   934,   936,   938,   940,   941,   943,
     944,   947,   950,   955,   956,   960,   964,   968,   973,   974,
     977,   979,   983,   987,   990,   995,  1000,  1006,  1013,  1014,
    1016,  1018,  1021,  1023,  1025,  1027,  1029,  1031,  1034,  1037,
    1039,  1042,  1045,  1049,  1052,  1055,  1058,  1064,  1072,  1080,
    1090,  1102,  1112,  1114,  1119,  1123,  1125,  1127,  1129,  1131,
    1133,  1135,  1137,  1139,  1141,  1146,  1151,  1152,  1156,  1160,
    1164,  1167,  1170,  1173,  1177,  1181,  1184,  1187,  1190,  1193,
    1196,  1199,  1205,  1210,  1215,  1223,  1227,  1235,  1238,  1241,
    1244,  1251,  1258,  1260,  1262,  1265,  1268,  1275,  1282,  1289,
    1293,  1296,  1303,  1310,  1314,  1319,  1324,  1329,  1335,  1339,
    1344,  1350,  1356,  1362,  1369,  1374,  1375,  1377,  1384,  1389,
    1391,  1393,  1395,  1397,  1399,  1401,  1403,  1405,  1407,  1409,
    1411,  1413,  1415,  1417,  1419,  1421,  1423,  1425,  1427,  1429,
    1431,  1433,  1435,  1437,  1439,  1441,  1443,  1445,  1447,  1449,
    1451,  1453,  1455,  1457,  1459,  1461,  1463,  1465,  1467,  1469,
    1471,  1473,  1475,  1477,  1479,  1481,  1483,  1485,  1487,  1489,
    1491,  1493,  1495,  1497,  1499,  1501,  1503,  1505,  1507,  1509,
    1511,  1513,  1515,  1517,  1519,  1521,  1523,  1525,  1527,  1529,
    1531,  1533,  1535,  1537,  1539,  1542,  1544,  1547,  1549,  1552,
    1554,  1556,  1558,  1562,  1566,  1568,  1570,  1572,  1575,  1580,
    1583,  1586,  1590,  1594,  1596,  1599,  1601,  1604,  1606,  1608,
    1610,  1612,  1614,  1616,  1618,  1620,  1622,  1624,  1626,  1628,
    1630,  1632,  1634,  1636,  1638,  1640,  1642,  1644,  1646,  1648,
    1650,  1652,  1654,  1656,  1658,  1660,  1662,  1664,  1666,  1668,
    1670,  1672,  1674,  1676,  1678,  1680,  1682,  1684,  1686,  1688,
    1690,  1692,  1694,  1696,  1698,  1700,  1702,  1704,  1706,  1708,
    1710,  1712,  1714,  1716,  1718,  1720,  1722,  1724,  1726,  1728,
    1730,  1737,  1744,  1751,  1758,  1766,  1774,  1782,  1789,  1797,
    1804,  1808,  1813,  1819,  1826,  1834,  1841,  1848,  1854,  1856,
    1858,  1861,  1864,  1867,  1873,  1874,  1876,  1880,  1886,  1892,
    1898,  1901,  1904,  1909,  1914,  1918,  1920,  1924,  1928,  1934,
    1941,  1949,  1954,  1957,  1959,  1961,  1963,  1965,  1967,  1969,
    1971,  1973,  1975,  1977,  1980,  1983,  1985,  1988,  1992,  1996,
    2000,  2004,  2006,  2008,  2013,  2017,  2021,  2023,  2025,  2030,
    2038,  2047,  2051,  2053,  2056,  2060,  2064,  2068,  2071,  2075,
    2079,  2083,  2087,  2090,  2094,  2098,  2102,  2105,  2109,  2113,
    2117,  2120,  2124,  2128,  2132,  2136,  2139,  2142,  2145,  2149,
    2153,  2157,  2161,  2165,  2169,  2173,  2177,  2180,  2183,  2186,
    2189,  2193,  2197,  2201,  2204,  2207,  2210,  2214,  2218,  2222,
    2227,  2232,  2237,  2240,  2244,  2248,  2252,  2256,  2260,  2262,
    2264,  2266,  2268,  2270,  2272,  2274,  2276,  2278,  2281,  2283,
    2285,  2287,  2291,  2293,  2295,  2297,  2298,  2302,  2304,  2306,
    2311,  2320,  2330,  2331,  2334,  2335,  2337,  2343,  2350,  2354,
    2359,  2370,  2377,  2384,  2391,  2398,  2405,  2412,  2419,  2426,
    2435,  2442,  2446,  2452,  2459,  2465,  2472,  2478,  2479,  2482,
    2485,  2487,  2489,  2492,  2495,  2499,  2501,  2503,  2504,  2506,
    2508,  2510,  2513,  2515,  2519,  2520,  2523,  2524,  2527,  2531,
    2533,  2542,  2555,  2557,  2558,  2561,  2563,  2567,  2571,  2573,
    2575,  2578,  2579,  2582,  2586,  2588,  2592,  2598,  2599,  2601,
    2607,  2611,  2616,  2624,  2625,  2629,  2633,  2637,  2642,  2646,
    2653,  2661,  2667,  2675,  2685,  2689,  2691,  2703,  2713,  2721,
    2722,  2724,  2725,  2727,  2730,  2735,  2740,  2743,  2745,  2749,
    2754,  2758,  2763,  2766,  2770,  2772,  2774,  2776,  2787,  2799,
    2810,  2821,  2831,  2847,  2860,  2867,  2874,  2880,  2886,  2893,
    2902,  2908,  2913,  2922,  2933,  2942,  2943,  2946,  2950,  2953,
    2957,  2966,  2972,  2977,  2993,  3009,  3013,  3017,  3021,  3029,
    3030,  3035,  3039,  3041,  3045,  3046,  3051,  3055,  3057,  3061,
    3062,  3067,  3071,  3073,  3077,  3083,  3087,  3089,  3091,  3097,
    3104,  3112,  3122,  3123,  3125,  3126,  3128,  3133,  3139,  3141,
    3143,  3147,  3151,  3153,  3156,  3158,  3160,  3163,  3166,  3172,
    3173,  3175,  3176,  3178,  3182,  3194,  3197,  3201,  3206,  3207,
    3211,  3212,  3217,  3222,  3223,  3225,  3227,  3232,  3236,  3238,
    3244,  3245,  3248,  3249,  3253,  3254,  3256,  3259,  3261,  3264,
    3267,  3269,  3278,  3289,  3297,  3298,  3300,  3302,  3305,  3308,
    3312,  3314,  3315,  3319,  3323,  3333,  3337,  3339,  3349,  3353,
    3361,  3367,  3371,  3373,  3375,  3378,  3380,  3383,  3388,  3389,
    3391,  3394,  3396,  3406,  3413,  3416,  3418,  3421,  3423,  3427,
    3429,  3431,  3433,  3439,  3446,  3454,  3461,  3468,  3473,  3474,
    3477,  3479,  3481,  3485,  3487,  3494,  3495,  3497,  3499,  3500,
    3504,  3505,  3507,  3510,  3512,  3515,  3519,  3524,  3530,  3537,
    3540,  3547,  3548,  3551,  3552,  3555,  3557,  3562,  3569,  3577,
    3585,  3586,  3588,  3592,  3593,  3597,  3601,  3606,  3609,  3614,
    3617,  3621,  3623,  3628,  3629,  3633,  3637,  3641,  3645,  3648,
    3650,  3653,  3654,  3656,  3666,  3674,  3683,  3694,  3695,  3698,
    3700,  3701,  3705,  3709,  3711,  3713,  3714,  3718,  3723,  3727,
    3734,  3742,  3750,  3759,  3764,  3770,  3772,  3774,  3781,  3786,
    3791,  3797,  3804,  3811,  3814,  3817,  3821,  3828,  3835,  3838,
    3842,  3850,  3857,  3865,  3871,  3880,  3886,  3889,  3891,  3899,
    3903,  3905,  3907,  3909,  3913,  3915,  3919,  3928,  3937,  3939,
    3941,  3947,  3950,  3952,  3956,  3958,  3959,  3961,  3963,  3967,
    3969,  3973,  3977,  3983,  3985,  3989,  3993,  3995,  3997,  4001,
    4013,  4016,  4018,  4023,  4025,  4028,  4031,  4036,  4043,  4047,
    4049,  4050,  4054,  4066,  4067,  4071,  4075,  4077,  4079,  4081,
    4083,  4085,  4089,  4094,  4096,  4099,  4101,  4103,  4107,  4109,
    4110,  4113,  4116,  4120,  4122,  4129,  4133,  4135,  4146,  4157,
    4159,  4161,  4165,  4170,  4174,  4176,  4179,  4183,  4185,  4192,
    4196,  4198,  4209,  4210,  4212,  4213,  4215,  4216,  4220,  4221,
    4223,  4225,  4227,  4229,  4230,  4233,  4237,  4239,  4243,  4249,
    4252,  4253,  4255,  4258,  4260,  4263,  4266,  4270,  4272,  4279,
    4284,  4290,  4298,  4304,  4309,  4311,  4317,  4319,  4321,  4326,
    4328,  4334,  4338,  4339,  4341,  4343,  4350,  4354,  4356,  4362,
    4368,  4373,  4376,  4381,  4385,  4387,  4390,  4399,  4400,  4403,
    4407,  4409,  4413,  4415,  4417,  4422,  4426,  4428,  4432,  4434,
    4438,  4440,  4444,  4446,  4448,  4452,  4454,  4458,  4460,  4462,
    4464,  4468,  4470,  4474,  4478,  4480,  4484,  4488,  4490,  4493,
    4496,  4498,  4500,  4502,  4504,  4506,  4508,  4510,  4512,  4518,
    4522,  4524,  4527,  4532,  4539,  4540,  4542,  4545,  4548,  4551,
    4552,  4554,  4559,  4564,  4568,  4570,  4572,  4577,  4581,  4583,
    4587,  4589,  4592,  4594,  4596,  4600,  4602,  4604,  4606,  4608,
    4609,  4612,  4613,  4617,  4621,  4625,  4626,  4628,  4632,  4635,
    4636,  4639,  4640,  4644,  4649,  4650,  4653,  4658,  4660,  4662,
    4664,  4665,  4669,  4670,  4672,  4675,  4679,  4681,  4685,  4686,
    4688,  4690,  4691,  4694,  4697,  4706,  4717,  4720,  4723,  4727,
    4729,  4730,  4734,  4735,  4738,  4740,  4744,  4746,  4750,  4752,
    4755,  4757,  4763,  4770,  4774,  4779,  4785,  4792,  4796,  4800,
    4804,  4808,  4812,  4816,  4820,  4824,  4828,  4832,  4836,  4840,
    4844,  4848,  4852,  4856,  4860,  4864,  4868,  4873,  4876,  4879,
    4883,  4887,  4889,  4891,  4894,  4897,  4899,  4902,  4904,  4907,
    4910,  4914,  4918,  4921,  4924,  4928,  4931,  4935,  4938,  4941,
    4943,  4947,  4951,  4955,  4959,  4962,  4965,  4969,  4973,  4976,
    4979,  4983,  4987,  4989,  4993,  4997,  4999,  5005,  5009,  5011,
    5013,  5015,  5017,  5021,  5023,  5027,  5031,  5033,  5037,  5041,
    5043,  5046,  5049,  5052,  5054,  5056,  5058,  5060,  5062,  5064,
    5068,  5070,  5072,  5074,  5076,  5078,  5080,  5089,  5096,  5101,
    5104,  5108,  5110,  5112,  5116,  5118,  5120,  5122,  5128,  5132,
    5134,  5135,  5137,  5143,  5148,  5151,  5153,  5157,  5160,  5161,
    5164,  5167,  5169,  5173,  5180,  5187,  5192,  5198,  5204,  5211,
    5218,  5225,  5234,  5242,  5247,  5251,  5258,  5261,  5262,  5270,
    5274,  5276,  5278,  5281,  5284,  5285,  5292,  5293,  5297,  5301,
    5303,  5305,  5306,  5310,  5311,  5317,  5320,  5323,  5325,  5328,
    5331,  5334,  5336,  5339,  5342,  5344,  5348,  5352,  5354,  5360,
    5364,  5366,  5368,  5377,  5384,  5390,  5393,  5398,  5401,  5406,
    5409,  5414,  5416,  5418,  5419,  5422,  5426,  5430,  5432,  5437,
    5438,  5440,  5442,  5445,  5446,  5448,  5449,  5453,  5456,  5458,
    5460,  5462,  5464,  5468,  5470,  5472,  5476,  5481,  5485,  5487,
    5492,  5499,  5506,  5515,  5517,  5521,  5527,  5529,  5531,  5535,
    5541,  5545,  5551,  5559,  5561,  5563,  5567,  5573,  5578,  5585,
    5593,  5601,  5610,  5617,  5623,  5626,  5627,  5629,  5632,  5634,
    5636,  5638,  5640,  5642,  5645,  5647,  5655,  5659,  5665,  5666,
    5668,  5677,  5686,  5688,  5690,  5694,  5700,  5704,  5708,  5710,
    5713,  5714,  5716,  5719,  5720,  5722,  5725,  5727,  5731,  5735,
    5739,  5741,  5743,  5747,  5750,  5752,  5754,  5756,  5758,  5760,
    5762,  5764,  5766,  5768,  5770,  5772,  5774,  5776,  5778,  5780,
    5782,  5784,  5790,  5794,  5797,  5800,  5803,  5806,  5809,  5812,
    5815,  5818,  5821,  5824,  5827,  5829,  5833,  5839,  5845,  5851,
    5859,  5867,  5868,  5871,  5873,  5878,  5883,  5886,  5893,  5901,
    5904,  5906,  5910,  5913,  5915,  5919,  5921,  5922,  5925,  5927,
    5929,  5931,  5933,  5938,  5944,  5948,  5959,  5971,  5972,  5975,
    5983,  5987,  5993,  5998,  5999,  6002,  6006,  6009,  6013,  6019,
    6023,  6026,  6029,  6033,  6036,  6041,  6046,  6050,  6054,  6058,
    6060,  6063,  6065,  6067,  6069,  6073,  6077,  6082,  6087,  6092,
    6096,  6103,  6105,  6107,  6110,  6113,  6117,  6122,  6127,  6132,
    6136,  6143,  6151,  6158,  6165,  6173,  6180,  6185,  6190,  6191,
    6194,  6198,  6199,  6203,  6204,  6207,  6209,  6212,  6215,  6218,
    6222,  6226,  6230,  6234,  6241,  6249,  6258,  6266,  6271,  6280,
    6288,  6293,  6296,  6299,  6306,  6313,  6321,  6330,  6335,  6339,
    6341,  6344,  6349,  6355,  6359,  6366,  6367,  6369,  6372,  6375,
    6380,  6385,  6391,  6398,  6403,  6406,  6409,  6410,  6412,  6415,
    6417,  6419,  6420,  6422,  6425,  6429,  6431,  6434,  6436,  6439,
    6441,  6443,  6445,  6447,  6451,  6453,  6455,  6456,  6460,  6466,
    6475,  6478,  6483,  6488,  6492,  6495,  6499,  6503,  6508,  6510,
    6512,  6515,  6517,  6519,  6520,  6523,  6524,  6527,  6531,  6533,
    6538,  6540,  6542,  6543,  6545,  6547,  6548,  6550,  6552,  6553,
    6558,  6562,  6563,  6568,  6571,  6573,  6575,  6577,  6582,  6585,
    6590,  6594,  6605,  6606,  6609,  6612,  6616,  6621,  6626,  6632,
    6635,  6638,  6644,  6647,  6650,  6654,  6659,  6671,  6672,  6675,
    6676,  6678,  6682,  6683,  6685,  6687,  6689,  6690,  6692,  6695,
    6702,  6709,  6716,  6722,  6728,  6734,  6738,  6740,  6742,  6745,
    6750,  6755,  6760,  6767,  6774,  6778,  6782,  6787,  6790,  6795,
    6800,  6804,  6806,  6807,  6810,  6813,  6818,  6823,  6828,  6835,
    6842,  6843,  6846,  6848,  6850,  6853,  6858,  6863,  6868,  6875,
    6882,  6885,  6888,  6889,  6891,  6892,  6894,  6897,  6898,  6900,
    6901,  6904,  6908,  6909,  6911,  6914,  6917,  6920,  6921,  6925,
    6929,  6931,  6935,  6936,  6941,  6943
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int16 yyrhs[] =
{
     422,     0,    -1,   423,    -1,   422,   423,    -1,   424,    -1,
     508,    -1,   498,    -1,     3,    -1,   494,    -1,   446,    -1,
     496,    -1,    38,    -1,   497,    -1,   397,   444,   398,    -1,
     425,    -1,   426,   399,   444,   400,    -1,   426,   397,   398,
      -1,   426,   397,   427,   398,    -1,   426,   401,   496,    -1,
     426,    54,   496,    -1,   426,    52,    -1,   426,    53,    -1,
     442,    -1,   427,   402,   442,    -1,   426,    -1,    52,   428,
      -1,    53,   428,    -1,   429,   430,    -1,    25,   428,    -1,
      25,   397,   478,   398,    -1,   403,    -1,   404,    -1,   405,
      -1,   406,    -1,   407,    -1,   408,    -1,   428,    -1,   397,
     478,   398,   430,    -1,   430,    -1,   431,   404,   430,    -1,
     431,   409,   430,    -1,   431,   410,   430,    -1,   431,    -1,
     432,   405,   431,    -1,   432,   406,   431,    -1,   432,    -1,
     433,    59,   432,    -1,   433,    58,   432,    -1,   433,    -1,
     434,   411,   433,    -1,   434,   412,   433,    -1,   434,    61,
     433,    -1,   434,    62,   433,    -1,   434,    -1,   435,    56,
     434,    -1,   435,    57,   434,    -1,   435,    -1,   436,   403,
     435,    -1,   436,    -1,   437,   413,   436,    -1,   437,    -1,
     438,   414,   437,    -1,   438,    -1,   439,    55,   438,    -1,
     439,    -1,   440,    60,   439,    -1,   440,    -1,   440,   415,
     440,   416,   441,    -1,   441,    -1,   428,   443,   442,    -1,
     417,    -1,    46,    -1,    47,    -1,    48,    -1,    44,    -1,
      45,    -1,    43,    -1,    42,    -1,    49,    -1,    50,    -1,
      51,    -1,   442,    -1,   444,   402,   442,    -1,   441,    -1,
     447,   418,    -1,   447,   448,   418,    -1,   451,    -1,   451,
     447,    -1,   452,    -1,   452,   447,    -1,   450,    -1,   448,
     449,   450,    -1,   402,    -1,   467,    -1,   467,   417,   481,
      -1,    29,    -1,    15,    -1,    26,    -1,     4,    -1,    21,
      -1,     7,    -1,     8,    -1,     7,    80,    -1,     8,    80,
      -1,    23,    -1,    19,    -1,    20,    -1,    24,    -1,    31,
      -1,    16,    -1,    13,    -1,     9,    -1,    33,    -1,    32,
      -1,   454,    -1,   464,    -1,    40,    -1,    63,    -1,    64,
      -1,    65,    -1,    66,    -1,    67,    -1,    68,    -1,    69,
      -1,    70,    -1,    71,    -1,    72,    -1,    73,    -1,    74,
      -1,    75,    -1,    76,    -1,    77,    -1,    78,    -1,    79,
      -1,    -1,    81,    -1,   457,   455,   419,   453,    -1,   457,
     455,   458,   419,   453,    -1,   457,   456,   419,   453,    -1,
     457,   456,   458,   419,   453,    -1,   457,   496,    -1,   496,
     420,    -1,   420,    -1,    27,    -1,    30,    -1,   459,    -1,
     458,   459,    -1,   460,    -1,   498,    -1,   472,   461,   418,
      -1,    -1,   463,    -1,   461,   462,   463,    -1,   402,    -1,
     467,    -1,   416,   445,    -1,   467,   416,   445,    -1,    14,
     420,   465,   419,    -1,    14,   496,   420,   465,   419,    -1,
      14,   496,    -1,   466,    -1,   465,   402,   466,    -1,   496,
      -1,   496,   417,   445,    -1,   468,    -1,   471,   468,    -1,
     496,    -1,   397,   467,   398,    -1,   468,   399,   400,    -1,
     468,   469,   445,   400,    -1,   468,   397,   398,    -1,   468,
     470,   475,   398,    -1,   468,   397,   473,   398,    -1,   399,
      -1,   397,    -1,   404,    -1,   404,   472,    -1,   404,   471,
      -1,   404,   472,   471,    -1,   452,    -1,   472,   452,    -1,
     474,    -1,   474,   402,    35,    -1,   496,    -1,   474,   402,
     496,    -1,   476,    -1,   476,   402,    35,    -1,   477,    -1,
     476,   402,   477,    -1,   472,   467,    -1,   478,    -1,   472,
      -1,   472,   479,    -1,   471,    -1,   480,    -1,   471,   480,
      -1,   397,   479,   398,    -1,   399,   400,    -1,   399,   445,
     400,    -1,   480,   399,   400,    -1,   480,   399,   445,   400,
      -1,   397,   398,    -1,   397,   475,   398,    -1,   480,   397,
     398,    -1,   480,   397,   475,   398,    -1,   442,    -1,   420,
     482,   419,    -1,   420,   482,   402,   419,    -1,   481,    -1,
     482,   402,   481,    -1,   484,    -1,   485,    -1,   490,    -1,
     491,    -1,   492,    -1,   493,    -1,   496,   416,   483,    -1,
     496,   416,   508,    -1,     6,   445,   416,   483,    -1,    11,
     416,   483,    -1,     6,   445,   416,   508,    -1,    11,   416,
     508,    -1,   488,   419,    -1,   488,   487,   419,    -1,   446,
      -1,   483,    -1,   508,    -1,   486,    -1,   487,   486,    -1,
     420,    -1,   446,    -1,   489,   446,    -1,   418,    -1,   444,
     418,    -1,    37,   397,   444,   398,   483,    -1,    37,   397,
     444,   398,   483,    36,   483,    -1,    28,   397,   444,   398,
     483,    -1,    34,   397,   444,   398,   483,    -1,    12,   483,
      34,   397,   444,   398,   418,    -1,    17,   397,   418,   418,
     398,   483,    -1,    17,   397,   418,   418,   444,   398,   483,
      -1,    17,   397,   418,   444,   418,   398,   483,    -1,    17,
     397,   418,   444,   418,   444,   398,   483,    -1,    17,   397,
     444,   418,   418,   398,   483,    -1,    17,   397,   444,   418,
     418,   444,   398,   483,    -1,    17,   397,   444,   418,   444,
     418,   398,   483,    -1,    17,   397,   444,   418,   444,   418,
     444,   398,   483,    -1,    18,   496,   418,    -1,    10,   418,
      -1,     5,   418,    -1,    22,   418,    -1,    22,   444,   418,
      -1,   467,   495,    -1,   447,   467,   495,    -1,   485,    -1,
     489,   485,    -1,    39,    -1,    41,    -1,    41,   497,    -1,
     499,    -1,   500,    -1,   501,    -1,   504,    -1,   505,    -1,
     502,    -1,   503,    -1,   506,    -1,   507,    -1,    82,    86,
      89,    87,    -1,    82,    88,    89,    88,    -1,    83,    97,
      -1,    83,    85,    -1,    84,    97,    -1,    90,    -1,    91,
      -1,    94,    97,    -1,    95,    97,    -1,    92,    -1,    93,
      -1,    98,   509,   551,   348,    -1,    98,   509,   510,   348,
      -1,    98,   509,   530,   348,    -1,    98,   509,   544,   272,
     348,    -1,    98,   509,   546,   348,    -1,    98,   547,   348,
      -1,    98,   548,   348,    -1,    98,   549,   348,    -1,    98,
     550,    -1,    -1,   111,   361,    -1,   111,   357,    -1,   511,
      -1,   519,    -1,   520,    -1,   521,    -1,   525,    -1,   526,
      -1,   527,    -1,   528,    -1,   529,    -1,   512,   789,   516,
      -1,   512,   361,   516,    -1,   136,   361,   513,   514,   133,
     515,   164,    -1,    -1,   391,    -1,   380,    -1,   364,    -1,
      -1,   390,    -1,    -1,   265,   377,    -1,   265,   227,    -1,
     265,   377,   265,   227,    -1,    -1,   164,   220,   384,    -1,
     164,   255,   517,    -1,   164,   255,   361,    -1,   164,   255,
     293,   356,    -1,    -1,   201,   518,    -1,  1096,    -1,   518,
     343,  1096,    -1,   136,   361,   240,    -1,   205,   361,    -1,
     205,   361,   257,  1097,    -1,   205,   361,   257,   537,    -1,
     161,   522,   361,   179,  1101,    -1,   161,   522,   361,   257,
     147,  1098,    -1,    -1,   166,    -1,   523,    -1,   523,   166,
      -1,   374,    -1,   215,    -1,   382,    -1,   381,    -1,   395,
      -1,   387,   524,    -1,   362,   524,    -1,   356,    -1,   342,
     356,    -1,   344,   356,    -1,   121,   388,   361,    -1,   121,
     361,    -1,   365,   204,    -1,   365,   202,    -1,   127,   357,
     283,   115,   357,    -1,   127,   357,   283,   115,   357,   205,
     357,    -1,   127,   357,   283,   115,   357,   257,   357,    -1,
     127,   357,   283,   115,   357,   257,   357,   343,   357,    -1,
     127,   357,   283,   115,   357,   257,   357,   343,   357,   205,
     357,    -1,   127,   357,   283,   115,   357,   257,   357,   205,
     357,    -1,   143,    -1,   556,   376,   270,  1099,    -1,   376,
     270,  1099,    -1,   531,    -1,   533,    -1,   534,    -1,   536,
      -1,   538,    -1,   540,    -1,   541,    -1,   542,    -1,   543,
      -1,   363,   372,   357,   532,    -1,   363,   372,   361,   532,
      -1,    -1,   265,   361,   356,    -1,   371,   372,   357,    -1,
     371,   372,   361,    -1,   535,   357,    -1,   535,   552,    -1,
     535,   553,    -1,   386,   361,   166,    -1,   371,   386,   361,
      -1,   147,  1098,    -1,   539,   357,    -1,   539,   552,    -1,
     539,   553,    -1,   157,   378,    -1,   157,   361,    -1,   556,
     157,   361,   257,  1097,    -1,   157,   361,   257,  1097,    -1,
     157,   361,   257,   537,    -1,   146,   116,   260,   164,   361,
     179,  1098,    -1,   164,   361,  1098,    -1,   146,   233,   361,
     164,   361,   179,  1098,    -1,   931,   348,    -1,   930,   348,
      -1,   932,   348,    -1,   157,   545,  1016,   348,   152,   348,
      -1,   157,   545,  1017,   348,   152,   348,    -1,   114,    -1,
     376,    -1,   366,   204,    -1,   366,   202,    -1,   104,   235,
     236,   365,   350,   248,    -1,   104,   235,   236,   365,   350,
     160,    -1,   104,   235,   236,   361,   350,   358,    -1,   225,
     159,   357,    -1,   253,   159,    -1,   385,   337,   393,   350,
     248,   338,    -1,   385,   337,   393,   350,   160,   338,    -1,
     394,   392,   130,    -1,   394,   392,   169,   361,    -1,   394,
     392,   373,   368,    -1,   394,   392,   373,   130,    -1,   394,
     392,   373,   361,   337,    -1,   394,   392,   361,    -1,   394,
     199,   375,   130,    -1,   394,   199,   375,   169,   361,    -1,
     394,   199,   375,   373,   368,    -1,   394,   199,   375,   373,
     130,    -1,   394,   199,   375,   373,   361,   337,    -1,   394,
     199,   375,   361,    -1,    -1,   393,    -1,   114,   136,   213,
     111,   361,   348,    -1,   152,   136,   213,   348,    -1,   552,
      -1,   553,    -1,   557,    -1,   558,    -1,   562,    -1,   563,
      -1,  1021,    -1,   566,    -1,   569,    -1,   570,    -1,   571,
      -1,   575,    -1,   576,    -1,   590,    -1,   598,    -1,   605,
      -1,   682,    -1,   740,    -1,   741,    -1,   644,    -1,   658,
      -1,   626,    -1,   627,    -1,   633,    -1,   635,    -1,   625,
      -1,   669,    -1,   665,    -1,   725,    -1,   726,    -1,   641,
      -1,   661,    -1,   732,    -1,   631,    -1,   632,    -1,   630,
      -1,   629,    -1,   587,    -1,   733,    -1,   734,    -1,   735,
      -1,   738,    -1,   739,    -1,  1077,    -1,  1079,    -1,   869,
      -1,  1011,    -1,  1012,    -1,  1013,    -1,  1014,    -1,  1015,
      -1,  1023,    -1,  1028,    -1,  1034,    -1,  1035,    -1,  1036,
      -1,  1039,    -1,  1037,    -1,  1040,    -1,  1058,    -1,  1060,
      -1,  1061,    -1,   603,    -1,   604,    -1,   724,    -1,   742,
      -1,  1080,    -1,  1083,    -1,  1085,    -1,   743,    -1,  1086,
      -1,  1094,    -1,  1095,    -1,   589,    -1,   588,    -1,   554,
     745,    -1,   745,    -1,   554,   746,    -1,   746,    -1,   554,
     753,    -1,   753,    -1,   767,    -1,   774,    -1,   789,   863,
     731,    -1,   755,   761,   864,    -1,   754,    -1,   556,    -1,
     555,    -1,   555,   556,    -1,   383,   357,   343,   357,    -1,
     164,   356,    -1,   164,   357,    -1,   361,   164,   356,    -1,
     361,   164,   357,    -1,   565,    -1,   565,   388,    -1,   567,
      -1,   567,   388,    -1,  1096,    -1,   102,    -1,   107,    -1,
     108,    -1,   112,    -1,   119,    -1,   126,    -1,   141,    -1,
     142,    -1,   151,    -1,   163,    -1,   377,    -1,   381,    -1,
     184,    -1,   189,    -1,   191,    -1,   194,    -1,   197,    -1,
     220,    -1,   222,    -1,   229,    -1,   312,    -1,   241,    -1,
     254,    -1,   257,    -1,   268,    -1,   153,    -1,   219,    -1,
     139,    -1,   162,    -1,   187,    -1,   269,    -1,   313,    -1,
     234,    -1,   249,    -1,   250,    -1,   270,    -1,   271,    -1,
     111,    -1,   185,    -1,   244,    -1,   195,    -1,   122,    -1,
     193,    -1,   212,    -1,   238,    -1,   221,    -1,   132,    -1,
     205,    -1,   121,    -1,   124,    -1,   292,    -1,   281,    -1,
     299,    -1,  1096,    -1,   138,    -1,   280,    -1,   215,    -1,
     374,    -1,   381,    -1,   382,    -1,   251,    -1,   290,    -1,
     104,   235,   236,   310,   350,   248,    -1,   104,   235,   236,
     310,   350,   160,    -1,   104,   235,   236,   310,   350,   137,
      -1,   104,   235,   236,   310,   350,   361,    -1,   104,   235,
     236,   361,   361,   350,   384,    -1,   104,   235,   236,   361,
     361,   350,   204,    -1,   104,   235,   236,   361,   361,   350,
     202,    -1,   104,   235,   236,   361,   350,   356,    -1,   104,
     235,   236,   361,   361,   350,   356,    -1,   104,   235,   236,
     361,   350,   361,    -1,   104,   361,   361,    -1,   104,   361,
     361,   361,    -1,   104,   361,   107,   361,   564,    -1,   104,
     361,   236,   361,   350,   356,    -1,   104,   361,   236,   361,
     350,   344,   356,    -1,   104,   361,   236,   361,   350,   361,
      -1,   104,   361,   236,   361,   350,   358,    -1,   104,   361,
     361,   281,   361,    -1,   239,    -1,   361,    -1,   125,   568,
      -1,   232,  1096,    -1,   230,   568,    -1,   230,   568,   246,
     232,  1096,    -1,    -1,   266,    -1,   236,   361,   572,    -1,
     104,   235,   236,   361,   572,    -1,   125,   568,   361,   135,
     276,    -1,   230,   568,   361,   135,   276,    -1,   220,   384,
      -1,   220,   267,    -1,   181,   186,   220,   361,    -1,   181,
     186,   361,   220,    -1,   181,   186,   361,    -1,  1096,    -1,
    1096,   345,  1096,    -1,  1096,   345,  1096,    -1,  1096,   345,
    1096,   345,  1096,    -1,   131,   256,  1096,   283,   115,  1096,
      -1,   131,   256,  1096,   283,   115,  1096,   577,    -1,   104,
     256,  1096,   579,    -1,   577,   578,    -1,   578,    -1,   583,
      -1,   584,    -1,   585,    -1,   580,    -1,   582,    -1,   583,
      -1,   584,    -1,   581,    -1,   580,    -1,   151,   361,    -1,
     142,   361,    -1,   585,    -1,   581,   585,    -1,   283,   115,
    1096,    -1,   243,   314,  1096,    -1,   137,   314,  1096,    -1,
     281,  1096,   586,    -1,   204,    -1,   202,    -1,   145,   256,
    1096,   660,    -1,   145,   277,  1096,    -1,   131,   277,  1096,
      -1,   591,    -1,   592,    -1,   170,   593,   246,   595,    -1,
     170,   593,   204,   573,   246,   595,   597,    -1,   170,   593,
     204,   141,  1096,   246,   595,   597,    -1,   593,   343,   594,
      -1,   594,    -1,   104,   361,    -1,   131,   106,   284,    -1,
     104,   106,   284,    -1,   145,   106,   284,    -1,   131,   217,
      -1,   131,   106,   217,    -1,   104,   106,   217,    -1,   145,
     106,   217,    -1,   157,   106,   217,    -1,   131,   247,    -1,
     131,   106,   247,    -1,   104,   106,   247,    -1,   145,   106,
     247,    -1,   131,   241,    -1,   131,   218,   241,    -1,   145,
     106,   241,    -1,   145,   218,   241,    -1,   131,   234,    -1,
     131,   106,   234,    -1,   104,   106,   234,    -1,   145,   106,
     234,    -1,   233,   106,   234,    -1,   131,   235,    -1,   104,
     235,    -1,   131,   242,    -1,   131,   106,   242,    -1,   104,
     106,   242,    -1,   138,   106,   242,    -1,   145,   106,   242,
      -1,   177,   106,   242,    -1,   306,   106,   242,    -1,   233,
     106,   242,    -1,   255,   106,   242,    -1,   131,   256,    -1,
     104,   256,    -1,   145,   256,    -1,   131,   261,    -1,   131,
     106,   261,    -1,   145,   106,   261,    -1,   170,   106,   216,
      -1,   131,   314,    -1,   104,   314,    -1,   145,   314,    -1,
     131,   106,   141,    -1,   145,   106,   141,    -1,   131,   296,
     261,    -1,   131,   106,   296,   261,    -1,   104,   106,   296,
     261,    -1,   145,   106,   296,   261,    -1,   131,   277,    -1,
     145,   106,   277,    -1,   170,   106,   277,    -1,   131,   106,
     361,    -1,   104,   106,   361,    -1,   145,   106,   361,    -1,
     104,    -1,   138,    -1,   157,    -1,   284,    -1,   177,    -1,
     223,    -1,   233,    -1,   255,    -1,   103,    -1,   103,   216,
      -1,   220,    -1,   267,    -1,  1096,    -1,   595,   343,   596,
      -1,   596,    -1,  1096,    -1,   218,    -1,    -1,   265,   170,
     385,    -1,   599,    -1,   600,    -1,   228,   593,   166,   595,
      -1,   228,   593,   204,   573,   166,   595,   601,   602,    -1,
     228,   593,   204,   141,  1096,   166,   595,   601,   602,    -1,
      -1,   117,   129,    -1,    -1,   361,    -1,   131,   241,   573,
     164,   573,    -1,   131,   218,   241,   573,   164,   573,    -1,
     145,   241,   573,    -1,   145,   218,   241,   573,    -1,   131,
     611,   310,  1096,   615,   616,   606,   265,   612,   617,    -1,
     104,   310,  1096,   100,   242,   618,    -1,   104,   310,  1096,
     145,   242,   618,    -1,   104,   310,  1096,   100,   361,   613,
      -1,   104,   310,  1096,   145,   361,   613,    -1,   104,   310,
    1096,   236,   361,   613,    -1,   104,   310,  1096,   236,   286,
     610,    -1,   104,   310,  1096,   236,   361,   657,    -1,   104,
     310,  1096,   236,   268,   356,    -1,   104,   310,  1096,   236,
     309,   151,   265,   609,    -1,   104,   310,  1096,   236,   309,
     142,    -1,   145,   310,  1096,    -1,   104,   310,  1096,   239,
     624,    -1,   104,   310,  1096,   239,   265,   309,    -1,   104,
     310,  1096,   361,   621,    -1,   104,   310,  1096,   361,   620,
     621,    -1,   104,   310,  1096,   163,   619,    -1,    -1,   361,
     607,    -1,   607,   608,    -1,   608,    -1,   361,    -1,   268,
     356,    -1,   309,   609,    -1,   609,   343,   358,    -1,   358,
      -1,   361,    -1,    -1,   610,    -1,   613,    -1,   361,    -1,
     613,   614,    -1,   614,    -1,   358,   343,   356,    -1,    -1,
     164,   361,    -1,    -1,   109,   361,    -1,   617,   343,   618,
      -1,   618,    -1,   166,  1096,   345,  1096,   246,  1096,   345,
    1096,    -1,   166,  1096,   345,  1096,   211,  1096,   246,  1096,
     345,  1096,   211,  1096,    -1,   345,    -1,    -1,   293,   356,
      -1,   103,    -1,   103,   293,   356,    -1,   384,   268,   356,
      -1,   384,    -1,   361,    -1,   268,   356,    -1,    -1,   242,
     622,    -1,   622,   343,   623,    -1,   623,    -1,  1096,   345,
    1096,    -1,  1096,   345,  1096,   211,  1096,    -1,    -1,   361,
      -1,   111,   361,   337,   356,   338,    -1,   315,   242,   573,
      -1,   289,   573,   246,  1096,    -1,   301,   242,   573,   246,
     113,   145,   628,    -1,    -1,   289,   246,  1096,    -1,   145,
     234,   573,    -1,   145,   284,   573,    -1,   145,   242,   573,
     640,    -1,   300,   242,   573,    -1,   321,   242,  1096,   337,
     634,   338,    -1,   211,  1096,   246,   242,  1096,   343,   634,
      -1,   211,  1096,   246,   242,  1096,    -1,   322,   242,  1096,
     636,   684,   639,   692,    -1,   211,   115,  1096,   337,   718,
     338,   337,   637,   338,    -1,   637,   343,   638,    -1,   638,
      -1,   242,  1096,   246,   211,  1096,   258,   185,   244,   337,
     688,   338,    -1,   242,  1096,   246,   211,  1096,   258,   337,
     688,   338,    -1,   242,  1096,   246,   211,  1096,   258,   137,
      -1,    -1,  1114,    -1,    -1,   117,    -1,   117,   129,    -1,
     104,   234,   573,   642,    -1,   104,   234,   573,   668,    -1,
     642,   643,    -1,   643,    -1,   239,   265,   356,    -1,   239,
     265,   344,   356,    -1,   361,   115,   356,    -1,   361,   115,
     344,   356,    -1,   361,   356,    -1,   361,   344,   356,    -1,
     361,    -1,   134,    -1,   198,    -1,   104,   242,   573,   100,
     659,   337,   701,   338,   692,  1115,    -1,   104,   242,   573,
     104,   659,   337,   559,   236,   137,   898,   338,    -1,   104,
     242,   573,   104,   659,   337,   559,   145,   137,   338,    -1,
     104,   242,   573,   104,   659,   337,   559,   199,   200,   338,
      -1,   104,   242,   573,   104,   659,   337,   559,   200,   338,
      -1,   104,   242,   573,   104,   659,   270,   337,   718,   338,
     271,   109,   337,   695,   338,  1115,    -1,   104,   242,   573,
     104,   659,   270,   271,   109,   337,   695,   338,  1115,    -1,
     104,   242,   573,   145,   659,   559,    -1,   104,   242,   573,
     289,   246,  1096,    -1,   104,   242,   573,   307,   356,    -1,
     104,   242,   573,   361,   645,    -1,   104,   242,   573,   103,
     284,   657,    -1,   104,   242,   573,   289,   123,   559,   246,
     559,    -1,   104,   242,   573,   281,  1114,    -1,   104,   242,
     573,   646,    -1,   104,   242,   573,   104,   314,  1096,   650,
     647,    -1,   104,   242,   573,   145,   190,   252,   337,   717,
     338,   660,    -1,   104,   242,   573,   289,   128,  1096,   246,
    1096,    -1,    -1,   211,  1096,    -1,   100,   656,   653,    -1,
     122,   211,    -1,   145,   211,  1096,    -1,   193,   212,  1096,
     343,  1096,   179,   656,   653,    -1,   289,   211,  1096,   246,
    1096,    -1,   281,   211,  1096,  1114,    -1,   238,   211,  1096,
     111,   337,   688,   338,   179,   337,   656,   653,   343,   656,
     653,   338,    -1,   238,   211,  1096,   258,   337,   688,   338,
     179,   337,   656,   653,   343,   656,   653,   338,    -1,   315,
     211,  1096,    -1,   151,   231,   195,    -1,   142,   231,   195,
      -1,   104,   211,  1096,   314,  1096,   650,   647,    -1,    -1,
     270,   337,   648,   338,    -1,   648,   343,   649,    -1,   649,
      -1,   559,   314,  1096,    -1,    -1,   284,   337,   651,   338,
      -1,   651,   343,   652,    -1,   652,    -1,  1096,   314,  1096,
      -1,    -1,   284,   337,   654,   338,    -1,   654,   343,   655,
      -1,   655,    -1,  1096,   211,  1096,    -1,  1096,   211,  1096,
     314,  1096,    -1,   211,  1096,  1112,    -1,   151,    -1,   142,
      -1,   104,   242,   573,   100,   699,    -1,   104,   242,   573,
     145,   128,  1096,    -1,   104,   242,   573,   145,   214,   183,
     660,    -1,   104,   242,   573,   145,   252,   337,   717,   338,
     660,    -1,    -1,   123,    -1,    -1,   117,    -1,   104,   284,
     573,   662,    -1,   104,   284,   573,   236,   663,    -1,   361,
      -1,   221,    -1,   221,   211,  1096,    -1,   289,   246,   573,
      -1,   663,    -1,   361,   664,    -1,   204,    -1,   202,    -1,
     350,   204,    -1,   350,   202,    -1,   131,   234,   573,   666,
     667,    -1,    -1,   642,    -1,    -1,   668,    -1,   657,   361,
     242,    -1,   670,   573,   204,   573,   337,   716,   338,   673,
     671,   672,   679,    -1,   131,   284,    -1,   131,   252,   284,
      -1,   131,   190,   252,   284,    -1,    -1,   361,   180,   361,
      -1,    -1,   236,   361,   350,   204,    -1,   236,   361,   350,
     202,    -1,    -1,   674,    -1,   190,    -1,   190,   337,   675,
     338,    -1,   675,   343,   676,    -1,   676,    -1,   211,  1096,
     204,  1096,   677,    -1,    -1,   314,  1096,    -1,    -1,   257,
     284,   679,    -1,    -1,   680,    -1,   680,   681,    -1,   681,
      -1,   314,  1096,    -1,   268,   356,    -1,   269,    -1,   131,
     242,   573,   337,   697,   338,   683,   692,    -1,   131,   242,
     573,   337,   697,   338,   683,   692,   109,   778,    -1,   131,
     242,   573,   683,   692,   109,   778,    -1,    -1,   722,    -1,
     690,    -1,   722,   690,    -1,   685,   684,    -1,   685,   684,
     690,    -1,  1114,    -1,    -1,   151,   231,   195,    -1,   142,
     231,   195,    -1,   211,   115,  1096,   337,   718,   338,   337,
     686,   338,    -1,   686,   343,   687,    -1,   687,    -1,   211,
    1096,   258,   185,   244,   337,   688,   338,  1112,    -1,   211,
    1096,  1112,    -1,   211,  1096,   258,   337,   688,   338,  1112,
      -1,   211,  1096,   258,   137,  1112,    -1,   688,   343,   689,
      -1,   689,    -1,   898,    -1,   690,   691,    -1,   691,    -1,
     314,  1096,    -1,   177,   361,   189,   356,    -1,    -1,   693,
      -1,   693,   694,    -1,   694,    -1,   270,   337,   718,   338,
     271,   109,   337,   695,   338,    -1,   270,   271,   109,   337,
     695,   338,    -1,   695,   696,    -1,   696,    -1,   314,  1096,
      -1,   361,    -1,   697,   343,   698,    -1,   698,    -1,   699,
      -1,   703,    -1,   700,   252,   715,   672,   678,    -1,   700,
     214,   183,   715,   672,   678,    -1,   700,   165,   183,   337,
     718,   338,   719,    -1,   700,   190,   252,   715,   672,   678,
      -1,   700,   190,   252,   867,   672,   678,    -1,   700,   120,
     873,   338,    -1,    -1,   128,  1096,    -1,   702,    -1,   699,
      -1,   702,   343,   703,    -1,   703,    -1,   559,   710,   704,
     705,   709,   706,    -1,    -1,   305,    -1,   259,    -1,    -1,
     174,   231,   356,    -1,    -1,   707,    -1,   707,   708,    -1,
     708,    -1,   700,   200,    -1,   700,   199,   200,    -1,   700,
     120,   873,   338,    -1,   700,   252,   867,   672,   678,    -1,
     700,   214,   183,   867,   672,   678,    -1,   700,   719,    -1,
     700,   190,   252,   867,   672,   678,    -1,    -1,   137,   898,
      -1,    -1,   711,   712,    -1,  1096,    -1,  1096,   337,   356,
     338,    -1,  1096,   337,   356,   343,   356,   338,    -1,  1096,
     337,   356,   343,   342,   356,   338,    -1,  1096,   337,   356,
     343,   344,   356,   338,    -1,    -1,   713,    -1,   361,   257,
     358,    -1,    -1,   337,   718,   338,    -1,   337,   717,   338,
      -1,   716,   343,   873,   867,    -1,   873,   867,    -1,   717,
     343,   559,   867,    -1,   559,   867,    -1,   718,   343,   559,
      -1,   559,    -1,   223,   573,   714,   720,    -1,    -1,   204,
     177,   721,    -1,   204,   255,   721,    -1,   204,   138,   721,
      -1,   204,   138,   117,    -1,   361,   361,    -1,   226,    -1,
     307,   356,    -1,    -1,   722,    -1,   131,   219,   573,   337,
     356,   704,   705,   338,   723,    -1,   131,   219,   573,   337,
     702,   338,   723,    -1,   131,   727,   261,   573,   728,   109,
     778,   731,    -1,   131,   206,   290,   727,   261,   573,   728,
     109,   778,   731,    -1,    -1,   361,   361,    -1,   361,    -1,
      -1,   337,   729,   338,    -1,   729,   343,   730,    -1,   730,
      -1,   559,    -1,    -1,   265,   220,   384,    -1,   104,   261,
     573,   126,    -1,   145,   261,   573,    -1,   131,   135,   276,
    1096,   257,  1096,    -1,   131,   736,   135,   276,  1096,   257,
    1096,    -1,   131,   135,   276,  1096,   737,   257,  1096,    -1,
     131,   736,   135,   276,  1096,   737,   257,  1096,    -1,   145,
     135,   276,  1096,    -1,   145,   736,   135,   276,  1096,    -1,
     218,    -1,   361,    -1,   127,   246,  1096,   283,   115,  1096,
      -1,   104,   135,   318,   239,    -1,   104,   135,   318,   361,
      -1,   104,   135,   318,   361,   361,    -1,   104,   235,   121,
     135,   276,   103,    -1,   104,   235,   121,   135,   276,  1096,
      -1,   137,   898,    -1,   227,   873,    -1,   145,   219,   573,
      -1,   124,   204,   242,   573,   180,   358,    -1,   124,   204,
     123,   574,   180,   358,    -1,   573,  1118,    -1,   337,   778,
     338,    -1,   138,   798,   799,   744,   806,   872,   861,    -1,
     177,   798,   179,   744,   137,   258,    -1,   177,   798,   179,
     744,   714,   258,   751,    -1,   177,   798,   179,   744,   778,
      -1,   177,   798,   179,   744,   337,   718,   338,   778,    -1,
     177,   798,   103,   747,   778,    -1,   747,   748,    -1,   748,
      -1,   179,   744,   773,   258,   337,   749,   338,    -1,   749,
     343,   750,    -1,   750,    -1,   898,    -1,   137,    -1,   751,
     343,   752,    -1,   752,    -1,   337,   749,   338,    -1,   255,
     798,   744,   806,   236,   762,   872,   861,    -1,   153,   179,
     573,   714,   258,   337,   749,   338,    -1,   756,    -1,   757,
      -1,   139,   802,  1100,   758,   872,    -1,   166,   759,    -1,
     760,    -1,  1096,   345,  1096,    -1,  1096,    -1,    -1,   162,
      -1,   187,    -1,   762,   343,   763,    -1,   763,    -1,   764,
     350,   898,    -1,   764,   350,   137,    -1,   337,   765,   338,
     350,   898,    -1,   559,    -1,  1096,   345,   559,    -1,   765,
     343,   766,    -1,   766,    -1,   559,    -1,  1096,   345,  1096,
      -1,   193,   798,   179,   573,  1118,   806,   257,   809,   204,
     873,   768,    -1,   768,   769,    -1,   769,    -1,   262,   770,
     245,   771,    -1,   361,    -1,   199,   361,    -1,   361,   361,
      -1,   255,   236,   762,   861,    -1,   177,   773,   258,   337,
     749,   338,    -1,   772,   343,   764,    -1,   764,    -1,    -1,
     337,   772,   338,    -1,   194,   798,   179,   573,  1118,   714,
     166,   573,   775,   872,   861,    -1,    -1,   337,   776,   338,
      -1,   776,   343,   777,    -1,   777,    -1,   898,    -1,   137,
      -1,   779,    -1,   780,    -1,   782,   860,   861,    -1,   784,
     782,   860,   861,    -1,   251,    -1,   251,   103,    -1,   178,
      -1,   285,    -1,   782,   781,   787,    -1,   787,    -1,    -1,
     265,   785,    -1,   265,   785,    -1,   785,   343,   786,    -1,
     786,    -1,  1096,   728,   109,   337,   779,   338,    -1,   337,
     782,   338,    -1,   788,    -1,   233,   798,   801,   802,   803,
     807,   872,   855,   800,   854,    -1,   233,   798,   801,   802,
    1100,   807,   872,   855,   800,   854,    -1,   790,    -1,   791,
      -1,   792,   860,   861,    -1,   793,   792,   860,   861,    -1,
     792,   781,   796,    -1,   796,    -1,   265,   794,    -1,   794,
     343,   795,    -1,   795,    -1,  1096,   728,   109,   337,   790,
     338,    -1,   337,   792,   338,    -1,   797,    -1,   233,   798,
     801,   802,  1102,   807,   872,   855,   800,   854,    -1,    -1,
     354,    -1,    -1,   166,    -1,    -1,   171,   115,   852,    -1,
      -1,   103,    -1,   144,    -1,   341,    -1,   804,    -1,    -1,
     179,   948,    -1,   804,   343,   805,    -1,   805,    -1,  1096,
     345,   341,    -1,  1096,   345,  1096,   345,   341,    -1,   898,
     806,    -1,    -1,  1096,    -1,   109,   559,    -1,   358,    -1,
     109,   358,    -1,   166,   808,    -1,   808,   343,   809,    -1,
     809,    -1,  1096,   345,  1096,  1118,   811,   806,    -1,  1096,
    1118,   811,   806,    -1,   337,   778,   338,   811,   806,    -1,
     319,   337,  1096,   343,   358,   338,   806,    -1,   320,   337,
     778,   338,   806,    -1,  1096,   332,  1096,   806,    -1,   842,
      -1,   242,   337,   810,   338,   806,    -1,   839,    -1,   913,
      -1,   302,   337,   926,   338,    -1,   361,    -1,  1096,   345,
    1096,   345,   559,    -1,  1096,   345,   559,    -1,    -1,   812,
      -1,   819,    -1,   294,   337,   813,   815,   816,   338,    -1,
     813,   343,   814,    -1,   814,    -1,   361,   337,   898,   338,
     806,    -1,   361,   337,   341,   338,   806,    -1,   164,   337,
     559,   338,    -1,   164,   559,    -1,   175,   337,   817,   338,
      -1,   817,   343,   818,    -1,   818,    -1,   837,   806,    -1,
     295,   820,   337,   821,   164,   821,   824,   338,    -1,    -1,
     361,   299,    -1,   337,   822,   338,    -1,   823,    -1,   822,
     343,   823,    -1,   823,    -1,   559,    -1,   175,   337,   825,
     338,    -1,   825,   343,   826,    -1,   826,    -1,   827,   109,
     830,    -1,   827,    -1,   337,   828,   338,    -1,   829,    -1,
     828,   343,   829,    -1,   829,    -1,   559,    -1,   337,   831,
     338,    -1,   832,    -1,   831,   343,   832,    -1,   832,    -1,
     833,    -1,   834,    -1,   834,   333,   835,    -1,   835,    -1,
     835,   342,   836,    -1,   835,   344,   836,    -1,   836,    -1,
     836,   341,   837,    -1,   836,   346,   837,    -1,   837,    -1,
     342,   838,    -1,   344,   838,    -1,   838,    -1,   200,    -1,
     356,    -1,   355,    -1,   358,    -1,   359,    -1,   328,    -1,
     329,    -1,  1096,   337,   840,   338,   806,    -1,   840,   343,
     841,    -1,   841,    -1,  1096,  1118,    -1,  1096,   345,  1096,
    1118,    -1,   809,   843,   182,   809,   204,   873,    -1,    -1,
     176,    -1,   184,   844,    -1,   229,   844,    -1,   167,   844,
      -1,    -1,   209,    -1,   389,   337,   846,   338,    -1,   370,
     337,   846,   338,    -1,   846,   343,   847,    -1,   847,    -1,
     898,    -1,   396,   337,   849,   338,    -1,   849,   343,   851,
      -1,   851,    -1,   849,   343,   850,    -1,   850,    -1,   337,
     338,    -1,   845,    -1,   898,    -1,   852,   343,   853,    -1,
     853,    -1,   845,    -1,   848,    -1,   898,    -1,    -1,   172,
     873,    -1,    -1,   856,   858,   859,    -1,   858,   859,   857,
      -1,   239,   265,   873,    -1,    -1,   856,    -1,   127,   115,
     873,    -1,   297,   873,    -1,    -1,   361,   192,    -1,    -1,
     207,   115,   865,    -1,   207,   361,   115,   865,    -1,    -1,
     189,   862,    -1,   189,   862,   343,   862,    -1,   356,    -1,
     357,    -1,   559,    -1,    -1,   164,   255,   864,    -1,    -1,
     361,    -1,   293,   356,    -1,   865,   343,   866,    -1,   866,
      -1,   898,   867,   868,    -1,    -1,   110,    -1,   140,    -1,
      -1,   299,   374,    -1,   299,   381,    -1,   306,   242,  1096,
     174,   870,   286,   864,   871,    -1,   306,   242,  1096,   345,
    1096,   174,   870,   286,   864,   871,    -1,   231,   361,    -1,
     361,   255,    -1,   361,   231,   361,    -1,   361,    -1,    -1,
     254,   382,   361,    -1,    -1,   263,   873,    -1,   874,    -1,
     874,   206,   875,    -1,   875,    -1,   875,   105,   876,    -1,
     876,    -1,   199,   877,    -1,   877,    -1,   898,   279,   898,
     105,   898,    -1,   898,   199,   279,   898,   105,   898,    -1,
     898,   188,   898,    -1,   898,   199,   188,   898,    -1,   898,
     188,   898,   154,   898,    -1,   898,   199,   188,   898,   154,
     898,    -1,   898,   878,   898,    -1,   898,   879,   898,    -1,
     898,   880,   898,    -1,   898,   881,   898,    -1,   898,   882,
     898,    -1,   898,   883,   898,    -1,   898,   884,   897,    -1,
     898,   885,   897,    -1,   898,   886,   897,    -1,   898,   887,
     897,    -1,   898,   888,   897,    -1,   898,   889,   897,    -1,
     898,   890,   897,    -1,   898,   891,   897,    -1,   898,   892,
     897,    -1,   898,   893,   897,    -1,   898,   894,   897,    -1,
     898,   895,   897,    -1,   898,   180,   200,    -1,   898,   180,
     199,   200,    -1,   280,   927,    -1,   252,   927,    -1,   896,
     336,   361,    -1,   896,   336,   375,    -1,   898,    -1,   350,
      -1,   349,   351,    -1,   335,   350,    -1,   349,    -1,   349,
     350,    -1,   351,    -1,   351,   350,    -1,   350,   103,    -1,
     349,   351,   103,    -1,   335,   350,   103,    -1,   199,   175,
      -1,   349,   103,    -1,   349,   350,   103,    -1,   351,   103,
      -1,   351,   350,   103,    -1,   350,   106,    -1,   350,   237,
      -1,   175,    -1,   349,   351,   106,    -1,   349,   351,   237,
      -1,   335,   350,   106,    -1,   335,   350,   237,    -1,   349,
     106,    -1,   349,   237,    -1,   349,   350,   106,    -1,   349,
     350,   237,    -1,   351,   106,    -1,   351,   237,    -1,   351,
     350,   106,    -1,   351,   350,   237,    -1,  1096,    -1,  1096,
     345,  1096,    -1,   337,   926,   338,    -1,   927,    -1,  1096,
     345,  1096,   345,   559,    -1,  1096,   345,   559,    -1,   559,
      -1,  1098,    -1,   838,    -1,   899,    -1,   899,   333,   900,
      -1,   900,    -1,   900,   342,   901,    -1,   900,   344,   901,
      -1,   901,    -1,   901,   341,   902,    -1,   901,   346,   902,
      -1,   902,    -1,   342,   903,    -1,   344,   903,    -1,   215,
     903,    -1,   903,    -1,   200,    -1,   248,    -1,   160,    -1,
     316,    -1,   317,    -1,   896,   336,   312,    -1,   356,    -1,
     355,    -1,   358,    -1,   359,    -1,   352,    -1,  1098,    -1,
    1096,   345,  1096,   345,  1096,   345,   559,   905,    -1,  1096,
     345,  1096,   345,   559,   905,    -1,  1096,   345,   559,   905,
      -1,   559,   905,    -1,   325,   345,   559,    -1,   186,    -1,
     913,    -1,   337,   926,   338,    -1,   927,    -1,   949,    -1,
     906,    -1,  1096,   345,  1096,   345,   559,    -1,  1096,   345,
     559,    -1,   559,    -1,    -1,   353,    -1,   118,   898,   907,
     910,   152,    -1,   118,   911,   910,   152,    -1,   907,   908,
      -1,   908,    -1,   262,   898,   909,    -1,   245,   898,    -1,
      -1,   149,   898,    -1,   911,   912,    -1,   912,    -1,   262,
     873,   909,    -1,  1096,   337,   926,   338,   914,   917,    -1,
    1096,   345,   560,   337,   926,   338,    -1,  1096,   337,   338,
     917,    -1,  1096,   345,   560,   337,   338,    -1,  1096,   337,
     341,   338,   917,    -1,  1096,   337,   103,   341,   338,   917,
      -1,  1096,   337,   103,   926,   338,   917,    -1,  1096,   337,
     144,   926,   338,   917,    -1,  1096,   345,  1096,   345,   560,
     337,   926,   338,    -1,  1096,   345,  1096,   345,   560,   337,
     338,    -1,   561,   337,   926,   338,    -1,   561,   337,   338,
      -1,   119,   337,   873,   109,   711,   338,    -1,   298,   904,
      -1,    -1,   278,   171,   337,   207,   115,   915,   338,    -1,
     915,   343,   916,    -1,   916,    -1,   898,    -1,   898,   110,
      -1,   898,   140,    -1,    -1,   210,   337,   918,   921,   922,
     338,    -1,    -1,   211,   115,   919,    -1,   919,   343,   920,
      -1,   920,    -1,   898,    -1,    -1,   207,   115,   865,    -1,
      -1,   361,   279,   923,   105,   924,    -1,   361,   923,    -1,
     361,   273,    -1,   275,    -1,   925,   273,    -1,   925,   274,
      -1,   361,   274,    -1,   275,    -1,   925,   273,    -1,   925,
     274,    -1,   356,    -1,   361,   356,   361,    -1,   926,   343,
     873,    -1,   873,    -1,   337,   783,   928,   861,   338,    -1,
     928,   781,   929,    -1,   929,    -1,   788,    -1,   933,   573,
     937,   227,   952,   936,   955,   941,    -1,   934,   573,   937,
     936,   955,   941,    -1,   935,   573,   936,   956,   941,    -1,
     131,   168,    -1,   131,   206,   290,   168,    -1,   131,   217,
      -1,   131,   206,   290,   217,    -1,   131,   250,    -1,   131,
     206,   290,   250,    -1,   109,    -1,   180,    -1,    -1,   337,
     338,    -1,   337,   938,   338,    -1,   938,   343,   939,    -1,
     939,    -1,  1096,   940,   952,   942,    -1,    -1,   174,    -1,
     208,    -1,   174,   208,    -1,    -1,  1096,    -1,    -1,   347,
     350,   945,    -1,   137,   945,    -1,   898,    -1,   873,    -1,
     873,    -1,  1096,    -1,  1096,   345,  1096,    -1,   913,    -1,
    1096,    -1,  1096,   337,   338,    -1,  1096,   337,   926,   338,
      -1,   948,   343,   950,    -1,   950,    -1,  1096,   339,   945,
     340,    -1,  1096,   345,  1096,   339,   945,   340,    -1,  1096,
     339,   945,   340,   345,   559,    -1,  1096,   345,  1096,   339,
     945,   340,   345,   559,    -1,  1096,    -1,  1096,   345,   559,
      -1,  1096,   345,  1096,   345,   559,    -1,   949,    -1,  1096,
      -1,   559,   336,   291,    -1,  1096,   345,   559,   336,   291,
      -1,   559,   336,   249,    -1,  1096,   345,   559,   336,   249,
      -1,  1096,   345,  1096,   345,   559,   336,   249,    -1,   953,
      -1,  1096,    -1,  1096,   345,  1096,    -1,  1096,   345,  1096,
     345,  1096,    -1,  1096,   337,   356,   338,    -1,  1096,   337,
     356,   343,   356,   338,    -1,  1096,   337,   356,   343,   342,
     356,   338,    -1,  1096,   337,   356,   343,   344,   356,   338,
      -1,   136,   957,   114,   977,   970,   152,   941,   348,    -1,
     114,   977,   970,   152,   941,   348,    -1,   957,   114,   977,
     970,   152,    -1,   960,   152,    -1,    -1,   958,    -1,   958,
     959,    -1,   959,    -1,   961,    -1,   962,    -1,   963,    -1,
     965,    -1,   960,   965,    -1,   965,    -1,   133,  1096,   937,
     180,   778,   863,   348,    -1,  1096,   155,   348,    -1,  1096,
     964,   952,   942,   348,    -1,    -1,   282,    -1,   249,  1096,
     180,   361,   337,   968,   338,   348,    -1,   249,  1096,   180,
     242,   201,   966,   967,   348,    -1,   953,    -1,  1096,    -1,
    1096,   345,  1096,    -1,  1096,   345,  1096,   345,  1096,    -1,
     284,   115,   711,    -1,   968,   343,   969,    -1,   969,    -1,
     559,   711,    -1,    -1,   971,    -1,   155,   972,    -1,    -1,
     973,    -1,   973,   974,    -1,   974,    -1,   262,   975,   987,
      -1,   262,   287,   987,    -1,   976,   206,   976,    -1,   976,
      -1,  1096,    -1,  1096,   345,  1096,    -1,   977,   978,    -1,
     978,    -1,   979,    -1,   982,    -1,  1002,    -1,  1003,    -1,
     983,    -1,  1005,    -1,   984,    -1,   988,    -1,   995,    -1,
    1006,    -1,  1007,    -1,   954,    -1,  1008,    -1,  1009,    -1,
    1010,    -1,   980,    -1,   349,   349,  1096,   351,   351,    -1,
     778,   863,   348,    -1,   746,   348,    -1,   753,   348,    -1,
     745,   348,    -1,   767,   348,    -1,   774,   348,    -1,   754,
     348,    -1,   569,   348,    -1,   566,   348,    -1,   565,   348,
      -1,   567,   348,    -1,   981,   348,    -1,   947,    -1,  1096,
     345,   947,    -1,   950,   347,   350,   945,   348,    -1,   236,
     950,   350,   945,   348,    -1,   161,  1096,   179,   948,   348,
      -1,   161,  1096,   345,  1096,   179,   948,   348,    -1,   173,
     944,   987,   985,   152,   173,   348,    -1,    -1,   149,   977,
      -1,   986,    -1,   303,   944,   987,   985,    -1,   150,   944,
     987,   985,    -1,   245,   977,    -1,   118,   989,   994,   152,
     118,   348,    -1,   118,   943,   991,   994,   152,   118,   348,
      -1,   990,   989,    -1,   990,    -1,   262,   944,   987,    -1,
     992,   991,    -1,   992,    -1,   262,   993,   987,    -1,   943,
      -1,    -1,   149,   977,    -1,   998,    -1,   997,    -1,   999,
      -1,  1001,    -1,   192,   977,   152,   192,    -1,   264,   944,
     996,   941,   348,    -1,   996,   941,   348,    -1,   164,   951,
    1119,   943,   334,   943,  1000,   996,   941,   348,    -1,   164,
     951,   174,   311,   943,   334,   943,  1000,   996,   941,   348,
      -1,    -1,   313,   943,    -1,   164,   951,  1119,   947,   996,
     941,   348,    -1,   121,  1096,   348,    -1,   121,  1096,   345,
    1096,   348,    -1,   158,   941,  1004,   348,    -1,    -1,   262,
     944,    -1,   169,  1096,   348,    -1,   200,   348,    -1,   205,
     947,   348,    -1,   205,  1096,   345,   947,   348,    -1,   288,
     976,   348,    -1,   288,   348,    -1,   227,   348,    -1,   227,
     945,   348,    -1,   130,   348,    -1,   104,   217,   573,   126,
      -1,   104,   168,   573,   126,    -1,   145,   217,   573,    -1,
     145,   168,   573,    -1,   145,   250,   573,    -1,  1019,    -1,
    1020,   946,    -1,   156,    -1,   157,    -1,   947,    -1,  1096,
     345,   947,    -1,  1105,   347,   350,    -1,   236,  1096,   350,
    1096,    -1,   236,   102,   350,   151,    -1,   236,   102,   350,
     142,    -1,   361,   350,  1051,    -1,   131,   135,  1096,  1022,
    1024,  1025,    -1,   108,    -1,   197,    -1,  1026,  1027,    -1,
    1027,  1026,    -1,   361,   236,  1096,    -1,   361,   361,   236,
    1096,    -1,   104,   135,  1096,  1032,    -1,   104,   135,  1096,
    1033,    -1,   104,   135,  1024,    -1,   104,   135,   112,   191,
     246,   358,    -1,   104,   135,   112,   314,  1096,   246,   358,
      -1,   104,   135,   112,   135,   246,   358,    -1,   104,   135,
     131,   361,   358,  1031,    -1,   104,   135,   289,   361,   358,
     246,   358,    -1,   104,   135,   222,   135,  1029,  1030,    -1,
     104,   135,   114,   361,    -1,   104,   135,   152,   361,    -1,
      -1,   254,   361,    -1,   254,   361,   358,    -1,    -1,   257,
     112,   191,    -1,    -1,   109,   358,    -1,   361,    -1,   361,
     361,    -1,   361,   378,    -1,   361,   158,    -1,   235,   121,
     356,    -1,   361,   125,   356,    -1,   361,   230,   356,    -1,
     145,   135,  1096,    -1,   131,   314,  1096,   361,  1041,  1046,
      -1,   131,   132,   314,  1096,   361,   356,  1043,    -1,   131,
     132,   314,  1096,   361,   356,   361,  1043,    -1,   131,   243,
     314,  1096,   361,  1041,  1048,    -1,   104,   314,  1096,  1053,
      -1,   104,   314,  1096,   289,   361,  1055,   246,  1055,    -1,
     104,   314,  1096,   104,   361,   358,  1054,    -1,   104,   314,
    1096,  1038,    -1,   114,   112,    -1,   152,   112,    -1,   104,
     314,  1096,   105,   361,  1041,    -1,   104,   314,  1096,   145,
     361,  1055,    -1,   104,   314,  1096,   104,   361,   358,  1044,
      -1,   104,   314,  1096,   104,   361,   358,   361,  1052,    -1,
     145,   314,  1096,  1057,    -1,  1041,   343,  1042,    -1,  1042,
      -1,   358,  1043,    -1,   358,   361,   356,  1043,    -1,   358,
     361,   356,   361,  1043,    -1,   358,   361,  1043,    -1,   358,
     361,   356,   361,   361,  1043,    -1,    -1,  1044,    -1,   361,
     202,    -1,   361,   204,    -1,   361,   204,   382,  1052,    -1,
     361,   204,   361,  1052,    -1,   361,   204,   382,   356,  1045,
      -1,   361,   204,   382,   356,   361,  1045,    -1,   361,   204,
     361,   361,    -1,   361,   361,    -1,   361,  1052,    -1,    -1,
    1047,    -1,  1047,  1047,    -1,  1049,    -1,  1050,    -1,    -1,
    1049,    -1,   304,  1052,    -1,   292,   361,   361,    -1,   356,
      -1,   356,   361,    -1,   356,    -1,   356,   361,    -1,   308,
      -1,   309,    -1,   308,    -1,   309,    -1,  1055,   343,  1056,
      -1,  1056,    -1,   358,    -1,    -1,   361,   361,   601,    -1,
     361,   361,   105,   361,   601,    -1,  1059,   573,  1062,   204,
     573,  1066,  1073,  1075,    -1,   131,   247,    -1,   131,   206,
     290,   247,    -1,   104,   247,   573,  1076,    -1,   145,   247,
     573,    -1,  1064,  1063,    -1,  1063,   206,   138,    -1,  1063,
     206,   177,    -1,  1063,   206,   255,  1065,    -1,   177,    -1,
     138,    -1,   255,  1065,    -1,   113,    -1,   101,    -1,    -1,
     201,   718,    -1,    -1,   224,  1067,    -1,  1067,   343,  1068,
      -1,  1068,    -1,  1069,  1070,  1071,  1072,    -1,   203,    -1,
     196,    -1,    -1,   231,    -1,   242,    -1,    -1,   109,    -1,
    1096,    -1,    -1,   164,   148,   231,  1074,    -1,   164,   148,
     240,    -1,    -1,   262,   337,   873,   338,    -1,   936,   955,
      -1,   151,    -1,   142,    -1,   126,    -1,  1078,  1096,   109,
     358,    -1,   131,   141,    -1,   131,   206,   290,   141,    -1,
     145,   141,  1096,    -1,   131,   296,   261,   573,   728,   683,
     692,  1081,   109,   779,    -1,    -1,   361,   361,    -1,   361,
    1082,    -1,   361,   361,  1082,    -1,   361,   361,   361,   361,
      -1,   361,   361,   361,  1082,    -1,   361,   361,   361,   361,
    1082,    -1,   204,   361,    -1,   204,   125,    -1,   104,   296,
     261,   573,  1084,    -1,   361,   361,    -1,   361,  1082,    -1,
     361,   361,  1082,    -1,   145,   296,   261,   573,    -1,   131,
     361,   361,  1018,  1019,   239,   898,  1087,  1088,  1090,  1092,
      -1,    -1,   152,   898,    -1,    -1,  1089,    -1,   361,   356,
     361,    -1,    -1,  1091,    -1,   151,    -1,   142,    -1,    -1,
    1093,    -1,   124,   358,    -1,   104,   361,   361,   236,  1018,
    1019,    -1,   104,   361,   361,   236,   239,   898,    -1,   104,
     361,   361,   236,   152,   898,    -1,   104,   361,   361,   236,
    1089,    -1,   104,   361,   361,   236,  1091,    -1,   104,   361,
     361,   236,  1093,    -1,   145,   361,   361,    -1,   361,    -1,
     360,    -1,   357,  1108,    -1,   367,   357,  1106,  1109,    -1,
     369,   357,  1106,  1109,    -1,  1097,   343,   357,  1108,    -1,
    1097,   343,   367,   357,  1106,  1109,    -1,  1097,   343,   369,
     357,  1106,  1109,    -1,   357,   174,  1108,    -1,   357,   208,
    1108,    -1,   357,   174,   208,  1108,    -1,   357,  1108,    -1,
     367,   357,  1106,  1109,    -1,   369,   357,  1106,  1109,    -1,
    1099,   343,   357,    -1,   357,    -1,    -1,   179,  1101,    -1,
     357,  1108,    -1,  1101,   343,   357,  1108,    -1,   367,   357,
    1106,  1109,    -1,   369,   357,  1106,  1109,    -1,  1101,   343,
     367,   357,  1106,  1109,    -1,  1101,   343,   369,   357,  1106,
    1109,    -1,    -1,   179,  1104,    -1,   357,    -1,   361,    -1,
    1103,  1108,    -1,  1104,   343,  1103,  1108,    -1,   367,  1103,
    1106,  1109,    -1,   369,  1103,  1106,  1109,    -1,  1104,   343,
     367,  1103,  1106,  1109,    -1,  1104,   343,   369,  1103,  1106,
    1109,    -1,   357,  1108,    -1,  1107,   357,    -1,    -1,   385,
      -1,    -1,  1109,    -1,  1110,   357,    -1,    -1,   379,    -1,
      -1,   314,  1096,    -1,  1111,   692,  1113,    -1,    -1,  1114,
      -1,   220,   384,    -1,   220,   267,    -1,   220,   361,    -1,
      -1,   337,  1116,   338,    -1,  1116,   343,  1117,    -1,  1117,
      -1,   211,  1096,   693,    -1,    -1,   211,   337,  1096,   338,
      -1,   175,    -1,   174,    -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   534,   534,   535,   539,   540,   541,   542,   556,   557,
     561,   562,   563,   564,   568,   569,   570,   571,   572,   573,
     574,   575,   579,   580,   584,   585,   586,   587,   588,   589,
     593,   594,   595,   596,   597,   598,   602,   603,   607,   608,
     609,   610,   614,   615,   616,   620,   621,   622,   626,   627,
     628,   629,   630,   634,   635,   636,   640,   641,   645,   646,
     650,   651,   655,   656,   660,   661,   665,   666,   670,   671,
     675,   676,   677,   678,   679,   680,   681,   682,   683,   684,
     685,   689,   690,   694,   698,   705,   771,   772,   773,   774,
     778,   923,  1045,  1090,  1091,  1095,  1099,  1107,  1108,  1109,
    1113,  1118,  1133,  1138,  1153,  1158,  1172,  1185,  1189,  1193,
    1199,  1205,  1206,  1207,  1213,  1220,  1226,  1234,  1240,  1246,
    1252,  1258,  1264,  1270,  1276,  1282,  1288,  1294,  1300,  1315,
    1321,  1327,  1334,  1339,  1347,  1349,  1356,  1370,  1393,  1407,
    1423,  1448,  1489,  1504,  1546,  1585,  1586,  1590,  1591,  1595,
    1631,  1635,  1746,  1860,  1904,  1905,  1906,  1910,  1911,  1912,
    1916,  1917,  1921,  1922,  1926,  1931,  1939,  1940,  1941,  1971,
    2014,  2015,  2019,  2023,  2033,  2041,  2046,  2051,  2056,  2064,
    2065,  2069,  2070,  2074,  2075,  2079,  2080,  2084,  2085,  2090,
    2159,  2163,  2164,  2168,  2169,  2170,  2174,  2175,  2176,  2177,
    2178,  2179,  2180,  2181,  2182,  2186,  2187,  2188,  2192,  2193,
    2197,  2198,  2199,  2200,  2201,  2202,  2206,  2208,  2209,  2210,
    2211,  2212,  2216,  2217,  2222,  2223,  2230,  2234,  2235,  2239,
    2249,  2250,  2254,  2255,  2259,  2260,  2261,  2265,  2266,  2267,
    2268,  2269,  2270,  2271,  2272,  2273,  2274,  2278,  2279,  2280,
    2281,  2282,  2286,  2287,  2291,  2292,  2296,  2321,  2322,  2332,
    2338,  2342,  2346,  2351,  2356,  2361,  2366,  2371,  2375,  2403,
    2435,  2468,  2506,  2514,  2580,  2656,  2697,  2738,  2774,  2812,
    2831,  2846,  2861,  2876,  2890,  2896,  2905,  2919,  2931,  2934,
    2954,  2972,  2976,  2981,  2986,  2991,  2995,  3000,  3005,  3010,
    3028,  3041,  3049,  3069,  3073,  3078,  3083,  3093,  3097,  3108,
    3112,  3117,  3124,  3133,  3135,  3143,  3144,  3145,  3148,  3150,
    3154,  3155,  3163,  3174,  3178,  3183,  3194,  3199,  3205,  3207,
    3208,  3209,  3213,  3217,  3221,  3225,  3229,  3233,  3237,  3244,
    3248,  3252,  3266,  3271,  3283,  3287,  3298,  3322,  3356,  3391,
    3433,  3483,  3532,  3540,  3544,  3558,  3563,  3568,  3573,  3578,
    3583,  3589,  3594,  3599,  3607,  3608,  3611,  3613,  3628,  3629,
    3633,  3663,  3675,  3689,  3706,  3724,  3728,  3758,  3765,  3775,
    3779,  3783,  3787,  3791,  3799,  3806,  3814,  3842,  3849,  3855,
    3861,  3875,  3892,  3903,  3908,  3913,  3918,  3925,  3932,  3950,
    3971,  3987,  3993,  4009,  4016,  4023,  4030,  4037,  4048,  4055,
    4062,  4069,  4076,  4083,  4094,  4104,  4106,  4113,  4121,  4138,
    4144,  4148,  4153,  4160,  4162,  4164,  4166,  4167,  4168,  4169,
    4171,  4172,  4174,  4175,  4177,  4179,  4180,  4181,  4182,  4183,
    4184,  4185,  4186,  4187,  4188,  4189,  4190,  4191,  4192,  4193,
    4194,  4195,  4196,  4197,  4198,  4199,  4200,  4201,  4202,  4203,
    4204,  4205,  4207,  4208,  4209,  4210,  4211,  4212,  4213,  4215,
    4217,  4218,  4219,  4221,  4222,  4223,  4224,  4225,  4227,  4228,
    4229,  4231,  4232,  4234,  4235,  4237,  4238,  4239,  4241,  4243,
    4244,  4245,  4247,  4248,  4254,  4265,  4275,  4286,  4297,  4308,
    4319,  4330,  4341,  4352,  4363,  4375,  4376,  4377,  4381,  4389,
    4410,  4421,  4452,  4480,  4484,  4492,  4496,  4510,  4511,  4512,
    4513,  4514,  4515,  4516,  4517,  4518,  4519,  4520,  4521,  4522,
    4523,  4524,  4525,  4526,  4527,  4528,  4529,  4530,  4531,  4532,
    4533,  4534,  4537,  4538,  4539,  4540,  4541,  4542,  4543,  4544,
    4545,  4546,  4547,  4548,  4549,  4550,  4551,  4552,  4553,  4554,
    4555,  4556,  4557,  4558,  4559,  4560,  4561,  4562,  4563,  4564,
    4565,  4572,  4573,  4574,  4575,  4576,  4577,  4578,  4583,  4584,
    4588,  4589,  4590,  4591,  4606,  4620,  4634,  4648,  4650,  4664,
    4669,  4696,  4731,  4744,  4757,  4770,  4783,  4796,  4814,  4815,
    4830,  4834,  4838,  4843,  4854,  4856,  4860,  4872,  4888,  4904,
    4919,  4921,  4922,  4937,  4950,  4966,  4967,  4971,  4972,  4976,
    4977,  4981,  4985,  4986,  4990,  4991,  4992,  4993,  4997,  4998,
    4999,  5000,  5001,  5005,  5006,  5010,  5011,  5015,  5019,  5023,
    5027,  5031,  5032,  5036,  5041,  5045,  5049,  5050,  5054,  5060,
    5065,  5073,  5074,  5079,  5091,  5092,  5093,  5094,  5095,  5096,
    5097,  5098,  5100,  5101,  5102,  5103,  5105,  5106,  5107,  5108,
    5109,  5110,  5111,  5112,  5113,  5114,  5115,  5116,  5117,  5118,
    5119,  5120,  5121,  5122,  5123,  5124,  5125,  5126,  5127,  5128,
    5129,  5130,  5131,  5132,  5133,  5134,  5136,  5137,  5139,  5140,
    5141,  5142,  5144,  5145,  5146,  5147,  5159,  5171,  5184,  5185,
    5186,  5187,  5188,  5189,  5190,  5191,  5192,  5193,  5195,  5196,
    5198,  5202,  5203,  5207,  5208,  5211,  5213,  5217,  5218,  5222,
    5227,  5232,  5239,  5241,  5244,  5246,  5262,  5267,  5276,  5279,
    5289,  5292,  5294,  5296,  5309,  5322,  5335,  5337,  5355,  5358,
    5361,  5364,  5365,  5366,  5368,  5387,  5402,  5406,  5408,  5423,
    5424,  5428,  5442,  5443,  5447,  5448,  5452,  5467,  5469,  5473,
    5474,  5489,  5490,  5494,  5497,  5499,  5513,  5515,  5531,  5532,
    5536,  5538,  5540,  5543,  5545,  5546,  5547,  5551,  5552,  5553,
    5565,  5568,  5570,  5574,  5575,  5579,  5580,  5583,  5585,  5597,
    5616,  5620,  5624,  5627,  5629,  5633,  5637,  5641,  5645,  5649,
    5653,  5654,  5658,  5662,  5666,  5667,  5671,  5672,  5673,  5676,
    5678,  5681,  5683,  5684,  5688,  5689,  5693,  5694,  5698,  5699,
    5700,  5713,  5726,  5743,  5756,  5773,  5774,  5778,  5784,  5787,
    5790,  5793,  5796,  5800,  5804,  5805,  5806,  5807,  5822,  5824,
    5827,  5828,  5830,  5832,  5836,  5840,  5842,  5846,  5847,  5848,
    5849,  5852,  5854,  5855,  5861,  5867,  5868,  5869,  5870,  5874,
    5876,  5881,  5882,  5886,  5889,  5891,  5896,  5897,  5901,  5904,
    5906,  5911,  5912,  5916,  5917,  5922,  5926,  5927,  5931,  5932,
    5933,  5935,  5941,  5943,  5946,  5948,  5952,  5953,  5957,  5958,
    5959,  5960,  5961,  5965,  5969,  5970,  5971,  5972,  5976,  5979,
    5981,  5984,  5986,  5990,  5994,  6009,  6010,  6011,  6014,  6016,
    6035,  6037,  6049,  6063,  6065,  6069,  6070,  6074,  6075,  6079,
    6083,  6085,  6088,  6090,  6093,  6095,  6099,  6100,  6104,  6107,
    6108,  6112,  6115,  6119,  6123,  6125,  6126,  6127,  6128,  6129,
    6131,  6135,  6137,  6138,  6143,  6149,  6150,  6155,  6158,  6159,
    6162,  6167,  6168,  6172,  6177,  6178,  6182,  6183,  6200,  6202,
    6206,  6207,  6211,  6214,  6219,  6220,  6224,  6225,  6243,  6244,
    6248,  6249,  6254,  6258,  6262,  6265,  6269,  6273,  6276,  6278,
    6282,  6283,  6287,  6288,  6292,  6296,  6298,  6299,  6302,  6304,
    6307,  6309,  6313,  6314,  6318,  6319,  6320,  6321,  6325,  6329,
    6330,  6334,  6336,  6339,  6341,  6345,  6346,  6347,  6349,  6351,
    6355,  6357,  6361,  6364,  6366,  6370,  6376,  6377,  6381,  6382,
    6386,  6387,  6391,  6395,  6397,  6398,  6399,  6400,  6405,  6418,
    6422,  6425,  6427,  6432,  6441,  6451,  6458,  6464,  6466,  6479,
    6493,  6495,  6499,  6500,  6504,  6507,  6509,  6514,  6519,  6524,
    6525,  6526,  6527,  6532,  6533,  6538,  6539,  6555,  6560,  6561,
    6573,  6598,  6599,  6604,  6608,  6613,  6617,  6618,  6626,  6627,
    6631,  6638,  6639,  6641,  6643,  6646,  6651,  6652,  6656,  6662,
    6663,  6667,  6668,  6672,  6673,  6676,  6680,  6688,  6699,  6703,
    6707,  6714,  6718,  6722,  6723,  6726,  6728,  6729,  6733,  6734,
    6738,  6739,  6740,  6745,  6746,  6750,  6751,  6755,  6756,  6763,
    6771,  6772,  6776,  6780,  6781,  6782,  6786,  6787,  6792,  6793,
    6796,  6798,  6805,  6811,  6813,  6817,  6818,  6822,  6823,  6830,
    6831,  6835,  6839,  6843,  6844,  6845,  6846,  6850,  6851,  6854,
    6856,  6860,  6864,  6865,  6869,  6873,  6874,  6878,  6885,  6895,
    6896,  6900,  6904,  6909,  6910,  6919,  6923,  6924,  6928,  6932,
    6933,  6937,  6946,  6948,  6951,  6953,  6956,  6958,  6961,  6963,
    6964,  6968,  6969,  6972,  6974,  6978,  6979,  6983,  6984,  6985,
    6988,  6990,  6991,  6992,  6993,  6997,  7001,  7002,  7006,  7007,
    7008,  7009,  7010,  7011,  7012,  7013,  7014,  7018,  7019,  7020,
    7021,  7022,  7025,  7027,  7028,  7032,  7036,  7037,  7041,  7042,
    7046,  7047,  7051,  7055,  7056,  7060,  7064,  7067,  7069,  7073,
    7074,  7078,  7079,  7083,  7087,  7091,  7092,  7096,  7097,  7101,
    7102,  7106,  7107,  7111,  7115,  7116,  7120,  7121,  7125,  7129,
    7133,  7134,  7138,  7139,  7140,  7144,  7145,  7146,  7150,  7151,
    7152,  7156,  7157,  7158,  7159,  7160,  7161,  7162,  7166,  7171,
    7172,  7176,  7177,  7182,  7186,  7188,  7189,  7190,  7191,  7194,
    7196,  7200,  7202,  7207,  7208,  7212,  7216,  7221,  7222,  7223,
    7224,  7228,  7232,  7233,  7237,  7238,  7242,  7243,  7244,  7247,
    7249,  7252,  7254,  7257,  7263,  7266,  7268,  7272,  7273,  7276,
    7278,  7292,  7294,  7295,  7311,  7313,  7314,  7318,  7319,  7343,
    7346,  7348,  7351,  7353,  7367,  7371,  7372,  7376,  7379,  7381,
    7382,  7385,  7387,  7388,  7395,  7397,  7402,  7417,  7430,  7444,
    7462,  7464,  7484,  7486,  7490,  7494,  7495,  7499,  7500,  7504,
    7505,  7509,  7511,  7513,  7515,  7517,  7519,  7521,  7523,  7525,
    7527,  7529,  7531,  7533,  7534,  7535,  7536,  7537,  7538,  7539,
    7540,  7541,  7542,  7543,  7544,  7545,  7546,  7547,  7548,  7549,
    7562,  7563,  7567,  7571,  7572,  7576,  7580,  7584,  7588,  7592,
    7596,  7597,  7598,  7602,  7606,  7610,  7614,  7618,  7619,  7620,
    7624,  7625,  7626,  7627,  7631,  7632,  7636,  7637,  7641,  7642,
    7646,  7647,  7651,  7652,  7656,  7657,  7658,  7659,  7660,  7661,
    7662,  7666,  7670,  7671,  7675,  7676,  7677,  7681,  7682,  7683,
    7687,  7688,  7689,  7690,  7694,  7695,  7696,  7697,  7698,  7699,
    7700,  7701,  7702,  7703,  7704,  7705,  7707,  7708,  7709,  7710,
    7711,  7712,  7713,  7714,  7715,  7716,  7717,  7722,  7723,  7724,
    7727,  7729,  7740,  7752,  7759,  7760,  7764,  7770,  7774,  7776,
    7781,  7782,  7786,  7794,  7797,  7799,  7802,  7804,  7807,  7810,
    7813,  7816,  7818,  7820,  7822,  7824,  7826,  7830,  7832,  7840,
    7841,  7845,  7846,  7847,  7851,  7853,  7861,  7863,  7868,  7869,
    7874,  7877,  7879,  7882,  7884,  7885,  7889,  7890,  7891,  7892,
    7896,  7897,  7898,  7899,  7903,  7904,  7908,  7909,  7913,  7917,
    7918,  7922,  7929,  7940,  7950,  7961,  7962,  7966,  7967,  7971,
    7972,  7976,  7977,  7983,  7985,  7986,  7992,  7993,  7997,  8003,
    8005,  8006,  8007,  8013,  8015,  8018,  8020,  8021,  8028,  8032,
    8037,  8044,  8045,  8046,  8053,  8054,  8055,  8062,  8063,  8067,
    8071,  8077,  8083,  8094,  8095,  8096,  8101,  8105,  8112,  8115,
    8120,  8123,  8128,  8135,  8136,  8137,  8140,  8151,  8152,  8154,
    8156,  8164,  8172,  8181,  8191,  8198,  8200,  8204,  8205,  8209,
    8210,  8211,  8212,  8219,  8220,  8227,  8240,  8247,  8254,  8256,
    8263,  8281,  8290,  8291,  8292,  8293,  8297,  8301,  8302,  8306,
    8312,  8314,  8318,  8321,  8323,  8327,  8328,  8332,  8335,  8341,
    8342,  8346,  8347,  8354,  8355,  8359,  8360,  8361,  8362,  8363,
    8364,  8365,  8366,  8367,  8368,  8369,  8370,  8371,  8372,  8373,
    8374,  8378,  8386,  8387,  8388,  8389,  8390,  8391,  8392,  8393,
    8394,  8395,  8396,  8397,  8401,  8402,  8409,  8414,  8425,  8430,
    8443,  8450,  8452,  8453,  8457,  8461,  8468,  8476,  8480,  8488,
    8489,  8493,  8499,  8500,  8504,  8510,  8513,  8515,  8522,  8523,
    8524,  8525,  8529,  8539,  8550,  8557,  8567,  8580,  8582,  8589,
    8602,  8603,  8611,  8617,  8619,  8623,  8627,  8631,  8632,  8640,
    8641,  8646,  8647,  8651,  8658,  8663,  8668,  8672,  8677,  8684,
    8688,  8692,  8693,  8697,  8698,  8702,  8706,  8707,  8708,  8712,
    8729,  8738,  8739,  8743,  8744,  8748,  8765,  8784,  8785,  8786,
    8787,  8788,  8789,  8790,  8803,  8816,  8818,  8831,  8844,  8846,
    8859,  8874,  8876,  8879,  8881,  8885,  8904,  8936,  8949,  8965,
    8966,  8979,  8995,  8999,  9014,  9033,  9067,  9085,  9088,  9104,
    9120,  9124,  9125,  9129,  9145,  9161,  9177,  9204,  9209,  9210,
    9214,  9216,  9230,  9255,  9269,  9294,  9296,  9300,  9314,  9328,
    9343,  9360,  9374,  9392,  9413,  9428,  9445,  9447,  9448,  9452,
    9453,  9456,  9458,  9462,  9466,  9470,  9471,  9491,  9492,  9512,
    9513,  9517,  9518,  9522,  9523,  9527,  9530,  9532,  9547,  9569,
    9579,  9580,  9584,  9588,  9592,  9596,  9597,  9598,  9599,  9600,
    9601,  9605,  9606,  9609,  9611,  9615,  9617,  9622,  9623,  9627,
    9634,  9635,  9638,  9640,  9641,  9644,  9646,  9650,  9653,  9655,
    9656,  9659,  9661,  9665,  9670,  9671,  9672,  9676,  9682,  9683,
    9687,  9691,  9699,  9701,  9761,  9776,  9811,  9873,  9914,  9967,
    9981,  9985,  9990, 10025, 10040, 10078, 10083, 10105, 10107, 10110,
   10112, 10116, 10120, 10122, 10127, 10128, 10132, 10134, 10139, 10143,
   10156, 10169, 10182, 10194, 10207, 10223, 10238, 10239, 10247, 10265,
   10276, 10287, 10298, 10309, 10323, 10334, 10345, 10356, 10367, 10378,
   10392, 10430, 10457, 10459, 10466, 10477, 10488, 10499, 10510, 10521,
   10534, 10536, 10543, 10544, 10548, 10559, 10570, 10581, 10592, 10603,
   10617, 10632, 10658, 10660, 10666, 10668, 10672, 10770, 10772, 10778,
   10780, 10783, 10786, 10788, 10792, 10793, 10794, 10810, 10812, 10818,
   10819, 10823, 10826, 10828, 10833, 10834
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "END_OF_FILE", "C_AUTO", "C_BREAK",
  "C_CASE", "C_CHAR", "C_VARCHAR", "C_CONST", "C_CONTINUE", "C_DEFAULT",
  "C_DO", "C_DOUBLE", "C_ENUM", "C_EXTERN", "C_FLOAT", "C_FOR", "C_GOTO",
  "C_INT", "C_LONG", "C_REGISTER", "C_RETURN", "C_SHORT", "C_SIGNED",
  "C_SIZEOF", "C_STATIC", "C_STRUCT", "C_SWITCH", "C_TYPEDEF", "C_UNION",
  "C_UNSIGNED", "C_VOID", "C_VOLATILE", "C_WHILE", "C_ELIPSIS", "C_ELSE",
  "C_IF", "C_CONSTANT", "C_IDENTIFIER", "C_TYPE_NAME", "C_STRING_LITERAL",
  "C_RIGHT_ASSIGN", "C_LEFT_ASSIGN", "C_ADD_ASSIGN", "C_SUB_ASSIGN",
  "C_MUL_ASSIGN", "C_DIV_ASSIGN", "C_MOD_ASSIGN", "C_AND_ASSIGN",
  "C_XOR_ASSIGN", "C_OR_ASSIGN", "C_INC_OP", "C_DEC_OP", "C_PTR_OP",
  "C_AND_OP", "C_EQ_OP", "C_NE_OP", "C_RIGHT_OP", "C_LEFT_OP", "C_OR_OP",
  "C_LE_OP", "C_GE_OP", "C_APRE_BINARY", "C_APRE_BIT", "C_APRE_BYTES",
  "C_APRE_VARBYTES", "C_APRE_NIBBLE", "C_APRE_INTEGER", "C_APRE_NUMERIC",
  "C_APRE_BLOB_LOCATOR", "C_APRE_CLOB_LOCATOR", "C_APRE_BLOB",
  "C_APRE_CLOB", "C_SQLLEN", "C_SQL_TIMESTAMP_STRUCT", "C_SQL_TIME_STRUCT",
  "C_SQL_DATE_STRUCT", "C_SQL_DA_STRUCT", "C_FAILOVERCB", "C_NCHAR_CS",
  "C_ATTRIBUTE", "M_INCLUDE", "M_DEFINE", "M_UNDEF", "M_FUNCTION",
  "M_LBRAC", "M_RBRAC", "M_DQUOTE", "M_FILENAME", "M_IF", "M_ELIF",
  "M_ELSE", "M_ENDIF", "M_IFDEF", "M_IFNDEF", "M_CONSTANT", "M_IDENTIFIER",
  "EM_SQLSTART", "EM_ERROR", "TR_ADD", "TR_AFTER", "TR_AGER", "TR_ALL",
  "TR_ALTER", "TR_AND", "TR_ANY", "TR_ARCHIVE", "TR_ARCHIVELOG", "TR_AS",
  "TR_ASC", "TR_AT", "TR_BACKUP", "TR_BEFORE", "TR_BEGIN", "TR_BY",
  "TR_BIND", "TR_CASCADE", "TR_CASE", "TR_CAST",
  "TR_CHECK_OPENING_PARENTHESIS", "TR_CLOSE", "TR_COALESCE", "TR_COLUMN",
  "TR_COMMENT", "TR_COMMIT", "TR_COMPILE", "TR_CONNECT", "TR_CONSTRAINT",
  "TR_CONSTRAINTS", "TR_CONTINUE", "TR_CREATE", "TR_VOLATILE", "TR_CURSOR",
  "TR_CYCLE", "TR_DATABASE", "TR_DECLARE", "TR_DEFAULT", "TR_DELETE",
  "TR_DEQUEUE", "TR_DESC", "TR_DIRECTORY", "TR_DISABLE", "TR_DISCONNECT",
  "TR_DISTINCT", "TR_DROP", "TR_DESCRIBE", "TR_DESCRIPTOR", "TR_EACH",
  "TR_ELSE", "TR_ELSEIF", "TR_ENABLE", "TR_END", "TR_ENQUEUE", "TR_ESCAPE",
  "TR_EXCEPTION", "TR_EXEC", "TR_EXECUTE", "TR_EXIT", "TR_FAILOVERCB",
  "TR_FALSE", "TR_FETCH", "TR_FIFO", "TR_FLUSH", "TR_FOR", "TR_FOREIGN",
  "TR_FROM", "TR_FULL", "TR_FUNCTION", "TR_GOTO", "TR_GRANT", "TR_GROUP",
  "TR_HAVING", "TR_IF", "TR_IN", "TR_IN_BF_LPAREN", "TR_INNER",
  "TR_INSERT", "TR_INTERSECT", "TR_INTO", "TR_IS", "TR_ISOLATION",
  "TR_JOIN", "TR_KEY", "TR_LEFT", "TR_LESS", "TR_LEVEL", "TR_LIFO",
  "TR_LIKE", "TR_LIMIT", "TR_LOCAL", "TR_LOGANCHOR", "TR_LOOP", "TR_MERGE",
  "TR_MOVE", "TR_MOVEMENT", "TR_NEW", "TR_NOARCHIVELOG", "TR_NOCYCLE",
  "TR_NOT", "TR_NULL", "TR_OF", "TR_OFF", "TR_OLD", "TR_ON", "TR_OPEN",
  "TR_OR", "TR_ORDER", "TR_OUT", "TR_OUTER", "TR_OVER", "TR_PARTITION",
  "TR_PARTITIONS", "TR_POINTER", "TR_PRIMARY", "TR_PRIOR", "TR_PRIVILEGES",
  "TR_PROCEDURE", "TR_PUBLIC", "TR_QUEUE", "TR_READ", "TR_REBUILD",
  "TR_RECOVER", "TR_REFERENCES", "TR_REFERENCING", "TR_REGISTER",
  "TR_RESTRICT", "TR_RETURN", "TR_REVOKE", "TR_RIGHT", "TR_ROLLBACK",
  "TR_ROW", "TR_SAVEPOINT", "TR_SELECT", "TR_SEQUENCE", "TR_SESSION",
  "TR_SET", "TR_SOME", "TR_SPLIT", "TR_START", "TR_STATEMENT",
  "TR_SYNONYM", "TR_TABLE", "TR_TEMPORARY", "TR_THAN", "TR_THEN", "TR_TO",
  "TR_TRIGGER", "TR_TRUE", "TR_TYPE", "TR_TYPESET", "TR_UNION",
  "TR_UNIQUE", "TR_UNREGISTER", "TR_UNTIL", "TR_UPDATE", "TR_USER",
  "TR_USING", "TR_VALUES", "TR_VARIABLE", "TR_VARIABLES", "TR_VIEW",
  "TR_WHEN", "TR_WHERE", "TR_WHILE", "TR_WITH", "TR_WORK", "TR_WRITE",
  "TR_PARALLEL", "TR_NOPARALLEL", "TR_LOB", "TR_STORE", "TR_ENDEXEC",
  "TR_PRECEDING", "TR_FOLLOWING", "TR_CURRENT_ROW", "TR_LINK", "TR_ROLE",
  "TR_WITHIN", "TK_BETWEEN", "TK_EXISTS", "TO_ACCESS", "TO_CONSTANT",
  "TO_IDENTIFIED", "TO_INDEX", "TO_MINUS", "TO_MODE", "TO_OTHERS",
  "TO_RAISE", "TO_RENAME", "TO_REPLACE", "TO_ROWTYPE", "TO_SEGMENT",
  "TO_WAIT", "TO_PIVOT", "TO_UNPIVOT", "TO_MATERIALIZED",
  "TO_CONNECT_BY_NOCYCLE", "TO_CONNECT_BY_ROOT", "TO_NULLS", "TO_PURGE",
  "TO_FLASHBACK", "TO_VC2COLL", "TA_ELSIF", "TA_EXTENTSIZE", "TA_FIXED",
  "TA_LOCK", "TA_MAXROWS", "TA_ONLINE", "TA_OFFLINE", "TA_REPLICATION",
  "TA_REVERSE", "TA_ROWCOUNT", "TA_STEP", "TA_TABLESPACE", "TA_TRUNCATE",
  "TA_SQLCODE", "TA_SQLERRM", "TA_LINKER", "TA_REMOTE_TABLE", "TA_SHARD",
  "TA_DISJOIN", "TA_CONJOIN", "TI_NONQUOTED_IDENTIFIER",
  "TI_QUOTED_IDENTIFIER", "TI_HOSTVARIABLE", "TL_TYPED_LITERAL",
  "TL_LITERAL", "TL_NCHAR_LITERAL", "TL_UNICODE_LITERAL", "TL_INTEGER",
  "TL_NUMERIC", "TS_AT_SIGN", "TS_CONCATENATION_SIGN", "TS_DOUBLE_PERIOD",
  "TS_EXCLAMATION_POINT", "TS_PERCENT_SIGN", "TS_OPENING_PARENTHESIS",
  "TS_CLOSING_PARENTHESIS", "TS_OPENING_BRACKET", "TS_CLOSING_BRACKET",
  "TS_ASTERISK", "TS_PLUS_SIGN", "TS_COMMA", "TS_MINUS_SIGN", "TS_PERIOD",
  "TS_SLASH", "TS_COLON", "TS_SEMICOLON", "TS_LESS_THAN_SIGN",
  "TS_EQUAL_SIGN", "TS_GREATER_THAN_SIGN", "TS_QUESTION_MARK",
  "TS_OUTER_JOIN_OPERATOR", "TX_HINTS", "SES_V_NUMERIC", "SES_V_INTEGER",
  "SES_V_HOSTVARIABLE", "SES_V_LITERAL", "SES_V_TYPED_LITERAL",
  "SES_V_DQUOTE_LITERAL", "SES_V_IDENTIFIER", "SES_V_ABSOLUTE",
  "SES_V_ALLOCATE", "SES_V_ASENSITIVE", "SES_V_AUTOCOMMIT", "SES_V_BATCH",
  "SES_V_BLOB_FILE", "SES_V_BREAK", "SES_V_CLOB_FILE", "SES_V_CUBE",
  "SES_V_DEALLOCATE", "SES_V_DESCRIPTOR", "SES_V_DO", "SES_V_FIRST",
  "SES_V_FOUND", "SES_V_FREE", "SES_V_HOLD", "SES_V_IMMEDIATE",
  "SES_V_INDICATOR", "SES_V_INSENSITIVE", "SES_V_LAST", "SES_V_NEXT",
  "SES_V_ONERR", "SES_V_ONLY", "APRE_V_OPTION", "SES_V_PREPARE",
  "SES_V_RELATIVE", "SES_V_RELEASE", "SES_V_ROLLUP", "SES_V_SCROLL",
  "SES_V_SENSITIVE", "SES_V_SQLERROR", "SES_V_THREADS", "SES_V_WHENEVER",
  "SES_V_CURRENT", "SES_V_GROUPING_SETS", "'('", "')'", "'['", "']'",
  "'.'", "','", "'&'", "'*'", "'+'", "'-'", "'~'", "'!'", "'/'", "'%'",
  "'<'", "'>'", "'^'", "'|'", "'?'", "':'", "'='", "';'", "'}'", "'{'",
  "$accept", "program", "combined_grammar", "C_grammar", "primary_expr",
  "postfix_expr", "argument_expr_list", "unary_expr", "unary_operator",
  "cast_expr", "multiplicative_expr", "additive_expr", "shift_expr",
  "relational_expr", "equality_expr", "and_expr", "exclusive_or_expr",
  "inclusive_or_expr", "logical_and_expr", "logical_or_expr",
  "conditional_expr", "assignment_expr", "assignment_operator", "expr",
  "constant_expr", "declaration", "declaration_specifiers",
  "init_declarator_list", "var_decl_list_begin", "init_declarator",
  "storage_class_specifier", "type_specifier", "attribute_specifier",
  "struct_or_union_specifier", "struct_decl_begin",
  "no_tag_struct_decl_begin", "struct_or_union",
  "struct_declaration_or_macro_list", "struct_declaration_or_macro",
  "struct_declaration", "struct_declarator_list", "struct_decl_list_begin",
  "struct_declarator", "enum_specifier", "enumerator_list", "enumerator",
  "declarator", "declarator2", "arr_decl_begin", "func_decl_begin",
  "pointer", "type_specifier_list", "parameter_identifier_list",
  "identifier_list", "parameter_type_list", "parameter_list",
  "parameter_declaration", "type_name", "abstract_declarator",
  "abstract_declarator2", "initializer", "initializer_list", "statement",
  "labeled_statement", "compound_statement", "super_compound_stmt",
  "super_compound_stmt_list", "compound_statement_begin",
  "declaration_list", "expression_statement", "selection_statement",
  "iteration_statement", "jump_statement", "function_definition",
  "function_body", "identifier", "string_literal", "Macro_grammar",
  "Macro_include", "Macro_define", "Macro_undef", "Macro_if", "Macro_elif",
  "Macro_ifdef", "Macro_ifndef", "Macro_else", "Macro_endif",
  "Emsql_grammar", "at_clause", "esql_stmt", "declare_cursor_stmt",
  "begin_declare", "cursor_sensitivity_opt", "cursor_scroll_opt",
  "cursor_hold_opt", "cursor_method_opt", "cursor_update_list",
  "cursor_update_column_list", "declare_statement_stmt",
  "open_cursor_stmt", "fetch_cursor_stmt", "fetch_orientation_from",
  "fetch_orientation", "fetch_integer", "close_cursor_stmt",
  "autocommit_stmt", "conn_stmt", "disconn_stmt", "free_lob_loc_stmt",
  "dsql_stmt", "alloc_descriptor_stmt", "with_max_option",
  "dealloc_descriptor_stmt", "prepare_stmt", "begin_prepare",
  "dealloc_prepared_stmt", "using_descriptor", "execute_immediate_stmt",
  "begin_immediate", "execute_stmt", "bind_stmt", "set_array_stmt",
  "select_list_stmt", "proc_stmt", "proc_func_begin", "etc_stmt",
  "option_stmt", "exception_stmt", "threads_stmt", "sharedptr_stmt",
  "sql_stmt", "direct_sql_stmt", "indirect_sql_stmt", "pre_clause",
  "onerr_clause", "for_clause", "commit_sql_stmt", "rollback_sql_stmt",
  "column_name", "memberfunc_name", "keyword_function_name",
  "alter_session_set_statement", "alter_system_statement",
  "archivelog_start_option", "commit_statement", "savepoint_statement",
  "rollback_statement", "opt_work_clause", "set_transaction_statement",
  "commit_force_database_link_statement",
  "rollback_force_database_link_statement", "transaction_mode",
  "user_object_name", "user_object_column_name", "create_user_statement",
  "alter_user_statement", "user_options", "create_user_option",
  "user_option", "disable_tcp_option", "access_options", "password_def",
  "temporary_tablespace", "default_tablespace", "access", "access_option",
  "drop_user_statement", "drop_role_statement", "create_role_statement",
  "grant_statement", "grant_system_privileges_statement",
  "grant_object_privileges_statement", "privilege_list", "privilege",
  "grantees_clause", "grantee", "opt_with_grant_option",
  "revoke_statement", "revoke_system_privileges_statement",
  "revoke_object_privileges_statement", "opt_cascade_constraints",
  "opt_force", "create_synonym_statement", "drop_synonym_statement",
  "replication_statement", "opt_repl_options", "repl_options",
  "repl_option", "offline_dirs", "repl_mode", "opt_repl_mode",
  "replication_with_hosts", "replication_hosts", "repl_host", "opt_role",
  "opt_conflict_resolution", "repl_tbl_commalist", "repl_tbl",
  "repl_flush_option", "repl_sync_retry", "opt_repl_sync_table",
  "repl_sync_table_commalist", "repl_sync_table", "repl_start_option",
  "truncate_table_statement", "rename_table_statement",
  "flashback_table_statement", "opt_flashback_rename",
  "drop_sequence_statement", "drop_index_statement",
  "drop_table_statement", "purge_table_statement",
  "disjoin_table_statement", "disjoin_partitioning_clause",
  "join_table_statement", "join_partitioning_clause",
  "join_table_attr_list", "join_table_attr", "join_table_options",
  "opt_drop_behavior", "alter_sequence_statement", "sequence_options",
  "sequence_option", "alter_table_statement", "opt_partition",
  "alter_table_partitioning", "opt_lob_storage", "lob_storage_list",
  "lob_storage_element", "opt_index_storage", "index_storage_list",
  "index_storage_element", "opt_index_part_attr_list",
  "index_part_attr_list", "index_part_attr", "partition_spec",
  "enable_or_disable", "alter_table_constraint_statement",
  "opt_column_tok", "opt_cascade_tok", "alter_index_statement",
  "alter_index_clause", "alter_index_set_clause", "on_off_clause",
  "create_sequence_statement", "opt_sequence_options",
  "opt_sequence_sync_table", "sequence_sync_table",
  "create_index_statement", "opt_index_uniqueness", "opt_index_type",
  "opt_index_pers", "opt_index_partitioning_clause",
  "local_partitioned_index", "on_partitioned_table_list",
  "on_partitioned_table", "opt_index_part_desc", "constr_using_option",
  "opt_index_attributes", "opt_index_attribute_list",
  "opt_index_attribute_element", "create_table_statement", "table_options",
  "opt_row_movement", "table_partitioning_clause", "part_attr_list",
  "part_attr", "part_key_cond_list", "part_key_cond",
  "table_TBS_limit_options", "table_TBS_limit_option",
  "opt_lob_attribute_list", "lob_attribute_list", "lob_attribute_element",
  "lob_storage_attribute_list", "lob_storage_attribute_element",
  "table_element_commalist", "table_element", "table_constraint_def",
  "opt_constraint_name", "column_def_commalist_or_table_constraint_def",
  "column_def_commalist", "column_def", "opt_variable_flag", "opt_in_row",
  "opt_column_constraint_def_list", "column_constraint_def_list",
  "column_constraint", "opt_default_clause", "opt_rule_data_type",
  "rule_data_type", "opt_encryption_attribute", "encryption_attribute",
  "opt_column_commalist", "key_column_with_opt_sort_mode_commalist",
  "expression_with_opt_sort_mode_commalist",
  "column_with_opt_sort_mode_commalist", "column_commalist",
  "references_specification", "opt_reference_spec", "referential_action",
  "table_maxrows", "opt_table_maxrows", "create_queue_statement",
  "create_view_statement", "create_or_replace_view_statement",
  "opt_no_force", "opt_view_column_def", "view_element_commalist",
  "view_element", "opt_with_read_only", "alter_view_statement",
  "drop_view_statement", "create_database_link_statement",
  "drop_database_link_statement", "link_type_clause", "user_clause",
  "alter_database_link_statement", "close_database_link_statement",
  "get_default_statement", "get_condition_statement",
  "drop_queue_statement", "comment_statement", "dml_table_reference",
  "delete_statement", "insert_statement", "multi_insert_value_list",
  "multi_insert_value", "insert_atom_commalist", "insert_atom",
  "multi_rows_list", "one_row", "update_statement", "enqueue_statement",
  "dequeue_statement", "dequeue_query_term", "dequeue_query_spec",
  "dequeue_from_clause", "dequeue_from_table_reference_commalist",
  "dequeue_from_table_reference", "opt_fifo", "assignment_commalist",
  "assignment", "set_column_def", "assignment_column_comma_list",
  "assignment_column", "merge_statement", "merge_actions_list",
  "merge_actions", "when_condition", "then_action",
  "table_column_commalist", "opt_table_column_commalist", "move_statement",
  "opt_move_expression_commalist", "move_expression_commalist",
  "move_expression", "select_or_with_select_statement", "select_statement",
  "with_select_statement", "set_op", "query_exp",
  "opt_subquery_factoring_clause", "subquery_factoring_clause",
  "subquery_factoring_clause_list", "subquery_factoring_element",
  "query_term", "query_spec", "select_or_with_select_statement_4emsql",
  "select_statement_4emsql", "with_select_statement_4emsql",
  "query_exp_4emsql", "subquery_factoring_clause_4emsql",
  "subquery_factoring_clause_list_4emsql",
  "subquery_factoring_element_4emsql", "query_term_4emsql",
  "query_spec_4emsql", "opt_hints", "opt_from", "opt_groupby_clause",
  "opt_quantifier", "target_list", "opt_into_list",
  "select_sublist_commalist", "select_sublist", "opt_as_name",
  "from_clause", "sel_from_table_reference_commalist",
  "sel_from_table_reference", "table_func_argument",
  "opt_pivot_or_unpivot_clause", "pivot_clause", "pivot_aggregation_list",
  "pivot_aggregation", "pivot_for", "pivot_in", "pivot_in_item_list",
  "pivot_in_item", "unpivot_clause", "opt_include_nulls", "unpivot_column",
  "unpivot_colname_list", "unpivot_colname", "unpivot_in",
  "unpivot_in_list", "unpivot_in_info", "unpivot_in_col_info",
  "unpivot_in_col_list", "unpivot_in_column", "unpivot_in_alias_info",
  "unpivot_in_alias_list", "unpivot_in_alias",
  "constant_arithmetic_expression", "constant_concatenation",
  "constant_addition_subtraction", "constant_multiplication_division",
  "constant_plus_minus_prior", "constant_terminal_expression",
  "dump_object_table", "dump_object_list", "dump_object", "joined_table",
  "opt_join_type", "opt_outer", "rollup_cube_clause",
  "rollup_cube_elements", "rollup_cube_element", "grouping_sets_clause",
  "grouping_sets_elements", "empty_group_operator",
  "grouping_sets_element", "group_concatenation",
  "group_concatenation_element", "opt_having_clause",
  "opt_hierarchical_query_clause", "start_with_clause",
  "opt_start_with_clause", "connect_by_clause", "opt_ignore_loop_clause",
  "opt_order_by_clause", "opt_limit_clause", "limit_value",
  "opt_for_update_clause", "opt_wait_clause",
  "sort_specification_commalist", "sort_specification", "opt_sort_mode",
  "opt_nulls_mode", "lock_table_statement", "table_lock_mode",
  "opt_until_next_ddl_clause", "opt_where_clause", "expression",
  "logical_or", "logical_and", "logical_not", "condition",
  "equal_operator", "not_equal_operator", "less_than_operator",
  "less_equal_operator", "greater_than_operator", "greater_equal_operator",
  "equal_all_operator", "not_equal_all_operator", "less_than_all_operator",
  "less_equal_all_operator", "greater_than_all_operator",
  "greater_equal_all_operator", "equal_any_operator",
  "not_equal_any_operator", "less_than_any_operator",
  "less_equal_any_operator", "greater_than_any_operator",
  "greater_equal_any_operator", "cursor_identifier",
  "quantified_expression", "arithmetic_expression", "concatenation",
  "addition_subtraction", "multiplication_division", "plus_minus_prior",
  "terminal_expression", "terminal_column", "opt_outer_join_operator",
  "case_expression", "case_when_value_list", "case_when_value",
  "case_then_value", "opt_case_else_clause", "case_when_condition_list",
  "case_when_condition", "unified_invocation", "opt_within_group_clause",
  "within_group_order_by_column_list", "within_group_order_by_column",
  "over_clause", "opt_over_partition_by_clause",
  "partition_by_column_list", "partition_by_column",
  "opt_over_order_by_clause", "opt_window_clause",
  "windowing_start_clause", "windowing_end_clause", "window_value",
  "list_expression", "subquery", "subquery_exp", "subquery_term",
  "SP_create_or_replace_function_statement",
  "SP_create_or_replace_procedure_statement",
  "SP_create_or_replace_typeset_statement",
  "create_or_replace_function_clause",
  "create_or_replace_procedure_clause", "create_or_replace_typeset_clause",
  "SP_as_o_is", "SP_parameter_declaration_commalist_option",
  "SP_parameter_declaration_commalist", "SP_parameter_declaration",
  "SP_parameter_access_mode_option", "SP_name_option",
  "SP_assign_default_value_option", "SP_arithmetic_expression",
  "SP_boolean_expression", "SP_unified_expression",
  "SP_function_opt_arglist", "SP_ident_opt_arglist",
  "SP_variable_name_commalist", "SP_arrayIndex_variable_name",
  "SP_variable_name", "SP_counter_name", "SP_data_type",
  "SP_rule_data_type", "SP_block", "SP_first_block", "SP_typeset_block",
  "SP_item_declaration_list_option", "SP_item_declaration_list",
  "SP_item_declaration", "SP_type_declaration_list",
  "SP_cursor_declaration", "SP_exception_declaration",
  "SP_variable_declaration", "SP_constant_option", "SP_type_declaration",
  "SP_array_element", "SP_opt_index_by_clause", "record_elem_commalist",
  "record_elem", "SP_exception_block_option", "SP_exception_block",
  "SP_exception_handler_list_option", "SP_exception_handler_list",
  "SP_exception_handler", "SP_exception_name_or_list", "SP_exception_name",
  "SP_statement_list", "SP_statement", "SP_label_statement",
  "SP_sql_statement", "SP_invocation_statement", "SP_assignment_statement",
  "SP_fetch_statement", "SP_if_statement", "SP_else_option", "SP_else_if",
  "SP_then_statement", "SP_case_statement", "SP_case_when_condition_list",
  "SP_case_when_condition", "SP_case_when_value_list",
  "SP_case_when_value", "SP_case_right_operand", "SP_case_else_option",
  "SP_loop_statement", "SP_common_loop", "SP_while_loop_statement",
  "SP_basic_loop_statement", "SP_for_loop_statement", "SP_step_option",
  "SP_cursor_for_loop_statement", "SP_close_statement",
  "SP_exit_statement", "SP_exit_when_option", "SP_goto_statement",
  "SP_null_statement", "SP_open_statement", "SP_raise_statement",
  "SP_return_statement", "SP_continue_statement",
  "SP_alter_procedure_statement", "SP_alter_function_statement",
  "SP_drop_procedure_statement", "SP_drop_function_statement",
  "SP_drop_typeset_statement", "exec_proc_stmt", "exec_func_stmt",
  "SP_exec_or_execute", "SP_ident_opt_simple_arglist",
  "assign_return_value", "set_statement", "initsize_spec",
  "create_database_statement", "archivelog_option", "character_set_option",
  "db_character_set", "national_character_set", "alter_database_statement",
  "until_option", "usinganchor_option", "filespec_option",
  "alter_database_options", "alter_database_options2",
  "drop_database_statement", "create_tablespace_statement",
  "create_temp_tablespace_statement", "alter_tablespace_dcl_statement",
  "backupTBS_option", "alter_tablespace_ddl_statement",
  "drop_tablespace_statement", "datafile_spec", "filespec",
  "autoextend_clause", "autoextend_statement", "maxsize_clause",
  "opt_createTBS_options", "tablespace_option", "opt_extentsize_option",
  "extentsize_clause", "segment_management_clause", "database_size_option",
  "size_option", "opt_alterTBS_onoff_options", "online_offline_option",
  "filename_list", "filename", "opt_droptablespace_options",
  "create_trigger_statement", "create_or_replace_trigger_clause",
  "alter_trigger_statement", "drop_trigger_statement",
  "trigger_event_clause", "trigger_event_type_list",
  "trigger_event_time_clause", "trigger_event_columns",
  "trigger_referencing_clause", "trigger_referencing_list",
  "trigger_referencing_item", "trigger_old_or_new", "trigger_row_or_table",
  "trigger_as_or_none", "trigger_referencing_name",
  "trigger_action_information", "trigger_when_condition",
  "trigger_action_clause", "alter_trigger_option",
  "create_or_replace_directory_statement",
  "create_or_replace_directory_clause", "drop_directory_statement",
  "create_materialized_view_statement", "opt_mview_build_refresh",
  "mview_refresh_time", "alter_materialized_view_statement",
  "mview_refresh_alter", "drop_materialized_view_statement",
  "create_job_statement", "opt_end_statement", "opt_interval_statement",
  "interval_statement", "opt_enable_statement", "enable_statement",
  "opt_job_comment_statement", "job_comment_statement",
  "alter_job_statement", "drop_job_statement", "object_name",
  "in_host_var_list", "host_variable", "free_lob_loc_list",
  "opt_into_host_var", "out_host_var_list", "opt_into_ses_host_var_4emsql",
  "out_1hostvariable_4emsql", "out_host_var_list_4emsql",
  "out_psm_host_var", "file_option", "option_keyword_opt", "indicator_opt",
  "indicator", "indicator_keyword_opt", "tablespace_name_option",
  "opt_table_part_desc", "opt_record_access", "record_access",
  "opt_partition_lob_attr_list", "partition_lob_attr_list",
  "partition_lob_attr", "opt_partition_name", "SES_V_IN", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
   token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,   267,   268,   269,   270,   271,   272,   273,   274,
     275,   276,   277,   278,   279,   280,   281,   282,   283,   284,
     285,   286,   287,   288,   289,   290,   291,   292,   293,   294,
     295,   296,   297,   298,   299,   300,   301,   302,   303,   304,
     305,   306,   307,   308,   309,   310,   311,   312,   313,   314,
     315,   316,   317,   318,   319,   320,   321,   322,   323,   324,
     325,   326,   327,   328,   329,   330,   331,   332,   333,   334,
     335,   336,   337,   338,   339,   340,   341,   342,   343,   344,
     345,   346,   347,   348,   349,   350,   351,   352,   353,   354,
     355,   356,   357,   358,   359,   360,   361,   362,   363,   364,
     365,   366,   367,   368,   369,   370,   371,   372,   373,   374,
     375,   376,   377,   378,   379,   380,   381,   382,   383,   384,
     385,   386,   387,   388,   389,   390,   391,   392,   393,   394,
     395,   396,   397,   398,   399,   400,   401,   402,   403,   404,
     405,   406,   407,   408,   409,   410,   411,   412,   413,   414,
     415,   416,   417,   418,   419,   420,   421,   422,   423,   424,
     425,   426,   427,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   443,   444,
     445,   446,   447,   448,   449,   450,   451,   452,   453,   454,
     455,   456,   457,   458,   459,   460,   461,   462,   463,   464,
     465,   466,   467,   468,   469,   470,   471,   472,   473,   474,
     475,   476,   477,   478,   479,   480,   481,   482,   483,   484,
     485,   486,   487,   488,   489,   490,   491,   492,   493,   494,
     495,   496,   497,   498,   499,   500,   501,   502,   503,   504,
     505,   506,   507,   508,   509,   510,   511,   512,   513,   514,
     515,   516,   517,   518,   519,   520,   521,   522,   523,   524,
     525,   526,   527,   528,   529,   530,   531,   532,   533,   534,
     535,   536,   537,   538,   539,   540,   541,   542,   543,   544,
     545,   546,   547,   548,   549,   550,   551,   552,   553,   554,
     555,   556,   557,   558,   559,   560,   561,   562,   563,   564,
     565,   566,   567,   568,   569,   570,   571,   572,   573,   574,
     575,   576,   577,   578,   579,   580,   581,   582,   583,   584,
     585,   586,   587,   588,   589,   590,   591,   592,   593,   594,
     595,   596,   597,   598,   599,   600,   601,   602,   603,   604,
     605,   606,   607,   608,   609,   610,   611,   612,   613,   614,
     615,   616,   617,   618,   619,   620,   621,   622,   623,   624,
     625,   626,   627,   628,   629,   630,   631,   632,   633,   634,
     635,   636,   637,   638,   639,   640,   641,   642,   643,   644,
     645,   646,   647,   648,   649,   650,   651,    40,    41,    91,
      93,    46,    44,    38,    42,    43,    45,   126,    33,    47,
      37,    60,    62,    94,   124,    63,    58,    61,    59,   125,
     123
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint16 yyr1[] =
{
       0,   421,   422,   422,   423,   423,   423,   423,   424,   424,
     425,   425,   425,   425,   426,   426,   426,   426,   426,   426,
     426,   426,   427,   427,   428,   428,   428,   428,   428,   428,
     429,   429,   429,   429,   429,   429,   430,   430,   431,   431,
     431,   431,   432,   432,   432,   433,   433,   433,   434,   434,
     434,   434,   434,   435,   435,   435,   436,   436,   437,   437,
     438,   438,   439,   439,   440,   440,   441,   441,   442,   442,
     443,   443,   443,   443,   443,   443,   443,   443,   443,   443,
     443,   444,   444,   445,   446,   446,   447,   447,   447,   447,
     448,   448,   449,   450,   450,   451,   451,   451,   451,   451,
     452,   452,   452,   452,   452,   452,   452,   452,   452,   452,
     452,   452,   452,   452,   452,   452,   452,   452,   452,   452,
     452,   452,   452,   452,   452,   452,   452,   452,   452,   452,
     452,   452,   452,   452,   453,   453,   454,   454,   454,   454,
     454,   455,   456,   457,   457,   458,   458,   459,   459,   460,
     461,   461,   461,   462,   463,   463,   463,   464,   464,   464,
     465,   465,   466,   466,   467,   467,   468,   468,   468,   468,
     468,   468,   468,   469,   470,   471,   471,   471,   471,   472,
     472,   473,   473,   474,   474,   475,   475,   476,   476,   477,
     477,   478,   478,   479,   479,   479,   480,   480,   480,   480,
     480,   480,   480,   480,   480,   481,   481,   481,   482,   482,
     483,   483,   483,   483,   483,   483,   484,   484,   484,   484,
     484,   484,   485,   485,   486,   486,   486,   487,   487,   488,
     489,   489,   490,   490,   491,   491,   491,   492,   492,   492,
     492,   492,   492,   492,   492,   492,   492,   493,   493,   493,
     493,   493,   494,   494,   495,   495,   496,   497,   497,   498,
     498,   498,   498,   498,   498,   498,   498,   498,   499,   499,
     500,   500,   501,   502,   503,   504,   505,   506,   507,   508,
     508,   508,   508,   508,   508,   508,   508,   508,   509,   509,
     509,   510,   510,   510,   510,   510,   510,   510,   510,   510,
     511,   511,   512,   513,   513,   513,   513,   514,   514,   515,
     515,   515,   515,   516,   516,   516,   516,   516,   517,   517,
     518,   518,   519,   520,   520,   520,   521,   521,   522,   522,
     522,   522,   523,   523,   523,   523,   523,   523,   523,   524,
     524,   524,   525,   525,   526,   526,   527,   527,   527,   527,
     527,   527,   528,   529,   529,   530,   530,   530,   530,   530,
     530,   530,   530,   530,   531,   531,   532,   532,   533,   533,
     534,   534,   534,   535,   536,   537,   538,   538,   538,   539,
     540,   540,   540,   540,   541,   542,   543,   544,   544,   544,
     544,   544,   545,   546,   546,   546,   546,   546,   546,   546,
     546,   547,   547,   548,   548,   548,   548,   548,   548,   548,
     548,   548,   548,   548,   548,   549,   549,   550,   550,   551,
     551,   551,   551,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   552,   552,   552,   552,   552,   552,
     552,   552,   552,   552,   553,   553,   553,   553,   553,   553,
     553,   553,   553,   553,   553,   554,   554,   554,   555,   556,
     556,   556,   556,   557,   557,   558,   558,   559,   559,   559,
     559,   559,   559,   559,   559,   559,   559,   559,   559,   559,
     559,   559,   559,   559,   559,   559,   559,   559,   559,   559,
     559,   559,   559,   559,   559,   559,   559,   559,   559,   559,
     559,   559,   559,   559,   559,   559,   559,   559,   559,   559,
     559,   559,   559,   559,   559,   559,   559,   559,   559,   559,
     559,   560,   560,   560,   560,   560,   560,   560,   561,   561,
     562,   562,   562,   562,   562,   562,   562,   562,   562,   562,
     563,   563,   563,   563,   563,   563,   563,   563,   564,   564,
     565,   566,   567,   567,   568,   568,   569,   569,   570,   571,
     572,   572,   572,   572,   572,   573,   573,   574,   574,   575,
     575,   576,   577,   577,   578,   578,   578,   578,   579,   579,
     579,   579,   579,   580,   580,   581,   581,   582,   583,   584,
     585,   586,   586,   587,   588,   589,   590,   590,   591,   592,
     592,   593,   593,   594,   594,   594,   594,   594,   594,   594,
     594,   594,   594,   594,   594,   594,   594,   594,   594,   594,
     594,   594,   594,   594,   594,   594,   594,   594,   594,   594,
     594,   594,   594,   594,   594,   594,   594,   594,   594,   594,
     594,   594,   594,   594,   594,   594,   594,   594,   594,   594,
     594,   594,   594,   594,   594,   594,   594,   594,   594,   594,
     594,   594,   594,   594,   594,   594,   594,   594,   594,   594,
     594,   595,   595,   596,   596,   597,   597,   598,   598,   599,
     600,   600,   601,   601,   602,   602,   603,   603,   604,   604,
     605,   605,   605,   605,   605,   605,   605,   605,   605,   605,
     605,   605,   605,   605,   605,   605,   605,   606,   606,   607,
     607,   608,   608,   608,   609,   609,   610,   611,   611,   612,
     612,   613,   613,   614,   615,   615,   616,   616,   617,   617,
     618,   618,   618,   619,   619,   619,   619,   620,   620,   620,
     620,   621,   621,   622,   622,   623,   623,   624,   624,   624,
     625,   626,   627,   628,   628,   629,   630,   631,   632,   633,
     634,   634,   635,   636,   637,   637,   638,   638,   638,   639,
     639,   640,   640,   640,   641,   641,   642,   642,   643,   643,
     643,   643,   643,   643,   643,   643,   643,   644,   644,   644,
     644,   644,   644,   644,   644,   644,   644,   644,   644,   644,
     644,   644,   644,   644,   644,   645,   645,   646,   646,   646,
     646,   646,   646,   646,   646,   646,   646,   646,   646,   647,
     647,   648,   648,   649,   650,   650,   651,   651,   652,   653,
     653,   654,   654,   655,   655,   656,   657,   657,   658,   658,
     658,   658,   659,   659,   660,   660,   661,   661,   662,   662,
     662,   662,   662,   663,   664,   664,   664,   664,   665,   666,
     666,   667,   667,   668,   669,   670,   670,   670,   671,   671,
     672,   672,   672,   673,   673,   674,   674,   675,   675,   676,
     677,   677,   678,   678,   679,   679,   680,   680,   681,   681,
     681,   682,   682,   682,   683,   683,   683,   683,   683,   683,
     683,   684,   684,   684,   685,   686,   686,   687,   687,   687,
     687,   688,   688,   689,   690,   690,   691,   691,   692,   692,
     693,   693,   694,   694,   695,   695,   696,   696,   697,   697,
     698,   698,   699,   699,   699,   699,   699,   699,   700,   700,
     701,   701,   702,   702,   703,   704,   704,   704,   705,   705,
     706,   706,   707,   707,   708,   708,   708,   708,   708,   708,
     708,   709,   709,   710,   710,   711,   711,   711,   711,   711,
     712,   712,   713,   714,   714,   715,   716,   716,   717,   717,
     718,   718,   719,   720,   720,   720,   720,   720,   721,   721,
     722,   723,   723,   724,   724,   725,   726,   727,   727,   727,
     728,   728,   729,   729,   730,   731,   731,   732,   733,   734,
     734,   734,   734,   735,   735,   736,   736,   737,   738,   738,
     738,   739,   739,   740,   741,   742,   743,   743,   744,   744,
     745,   746,   746,   746,   746,   746,   747,   747,   748,   749,
     749,   750,   750,   751,   751,   752,   753,   754,   755,   756,
     757,   758,   759,   760,   760,   761,   761,   761,   762,   762,
     763,   763,   763,   764,   764,   765,   765,   766,   766,   767,
     768,   768,   769,   770,   770,   770,   771,   771,   772,   772,
     773,   773,   774,   775,   775,   776,   776,   777,   777,   778,
     778,   779,   780,   781,   781,   781,   781,   782,   782,   783,
     783,   784,   785,   785,   786,   787,   787,   788,   788,   789,
     789,   790,   791,   792,   792,   793,   794,   794,   795,   796,
     796,   797,   798,   798,   799,   799,   800,   800,   801,   801,
     801,   802,   802,   803,   803,   804,   804,   805,   805,   805,
     806,   806,   806,   806,   806,   807,   808,   808,   809,   809,
     809,   809,   809,   809,   809,   809,   809,   810,   810,   810,
     810,   810,   811,   811,   811,   812,   813,   813,   814,   814,
     815,   815,   816,   817,   817,   818,   819,   820,   820,   821,
     821,   822,   822,   823,   824,   825,   825,   826,   826,   827,
     827,   828,   828,   829,   830,   830,   831,   831,   832,   833,
     834,   834,   835,   835,   835,   836,   836,   836,   837,   837,
     837,   838,   838,   838,   838,   838,   838,   838,   839,   840,
     840,   841,   841,   842,   843,   843,   843,   843,   843,   844,
     844,   845,   845,   846,   846,   847,   848,   849,   849,   849,
     849,   850,   851,   851,   852,   852,   853,   853,   853,   854,
     854,   855,   855,   855,   856,   857,   857,   858,   858,   859,
     859,   860,   860,   860,   861,   861,   861,   862,   862,   862,
     863,   863,   864,   864,   864,   865,   865,   866,   867,   867,
     867,   868,   868,   868,   869,   869,   870,   870,   870,   870,
     871,   871,   872,   872,   873,   874,   874,   875,   875,   876,
     876,   877,   877,   877,   877,   877,   877,   877,   877,   877,
     877,   877,   877,   877,   877,   877,   877,   877,   877,   877,
     877,   877,   877,   877,   877,   877,   877,   877,   877,   877,
     877,   877,   878,   879,   879,   880,   881,   882,   883,   884,
     885,   885,   885,   886,   887,   888,   889,   890,   890,   890,
     891,   891,   891,   891,   892,   892,   893,   893,   894,   894,
     895,   895,   896,   896,   897,   897,   897,   897,   897,   897,
     897,   898,   899,   899,   900,   900,   900,   901,   901,   901,
     902,   902,   902,   902,   903,   903,   903,   903,   903,   903,
     903,   903,   903,   903,   903,   903,   903,   903,   903,   903,
     903,   903,   903,   903,   903,   903,   903,   904,   904,   904,
     905,   905,   906,   906,   907,   907,   908,   909,   910,   910,
     911,   911,   912,   913,   913,   913,   913,   913,   913,   913,
     913,   913,   913,   913,   913,   913,   913,   914,   914,   915,
     915,   916,   916,   916,   917,   917,   918,   918,   919,   919,
     920,   921,   921,   922,   922,   922,   923,   923,   923,   923,
     924,   924,   924,   924,   925,   925,   926,   926,   927,   928,
     928,   929,   930,   931,   932,   933,   933,   934,   934,   935,
     935,   936,   936,   937,   937,   937,   938,   938,   939,   940,
     940,   940,   940,   941,   941,   942,   942,   942,   943,   944,
     945,   946,   946,   946,   947,   947,   947,   948,   948,   949,
     949,   949,   949,   950,   950,   950,   950,   951,   952,   952,
     952,   952,   952,   952,   952,   952,   952,   953,   953,   953,
     953,   954,   954,   955,   956,   957,   957,   958,   958,   959,
     959,   959,   959,   960,   960,   961,   962,   963,   964,   964,
     965,   965,   966,   966,   966,   966,   967,   968,   968,   969,
     970,   970,   971,   972,   972,   973,   973,   974,   974,   975,
     975,   976,   976,   977,   977,   978,   978,   978,   978,   978,
     978,   978,   978,   978,   978,   978,   978,   978,   978,   978,
     978,   979,   980,   980,   980,   980,   980,   980,   980,   980,
     980,   980,   980,   980,   981,   981,   982,   982,   983,   983,
     984,   985,   985,   985,   986,   986,   987,   988,   988,   989,
     989,   990,   991,   991,   992,   993,   994,   994,   995,   995,
     995,   995,   996,   997,   998,   999,   999,  1000,  1000,  1001,
    1002,  1002,  1003,  1004,  1004,  1005,  1006,  1007,  1007,  1008,
    1008,  1009,  1009,  1010,  1011,  1012,  1013,  1014,  1015,  1016,
    1017,  1018,  1018,  1019,  1019,  1020,  1021,  1021,  1021,  1022,
    1023,  1024,  1024,  1025,  1025,  1026,  1027,  1028,  1028,  1028,
    1028,  1028,  1028,  1028,  1028,  1028,  1028,  1028,  1029,  1029,
    1029,  1030,  1030,  1031,  1031,  1032,  1032,  1032,  1032,  1033,
    1033,  1033,  1034,  1035,  1035,  1035,  1036,  1037,  1037,  1037,
    1037,  1038,  1038,  1039,  1039,  1039,  1039,  1040,  1041,  1041,
    1042,  1042,  1042,  1042,  1042,  1043,  1043,  1044,  1044,  1044,
    1044,  1044,  1044,  1044,  1045,  1045,  1046,  1046,  1046,  1047,
    1047,  1048,  1048,  1049,  1050,  1051,  1051,  1052,  1052,  1053,
    1053,  1054,  1054,  1055,  1055,  1056,  1057,  1057,  1057,  1058,
    1059,  1059,  1060,  1061,  1062,  1063,  1063,  1063,  1063,  1063,
    1063,  1064,  1064,  1065,  1065,  1066,  1066,  1067,  1067,  1068,
    1069,  1069,  1070,  1070,  1070,  1071,  1071,  1072,  1073,  1073,
    1073,  1074,  1074,  1075,  1076,  1076,  1076,  1077,  1078,  1078,
    1079,  1080,  1081,  1081,  1081,  1081,  1081,  1081,  1081,  1082,
    1082,  1083,  1084,  1084,  1084,  1085,  1086,  1087,  1087,  1088,
    1088,  1089,  1090,  1090,  1091,  1091,  1092,  1092,  1093,  1094,
    1094,  1094,  1094,  1094,  1094,  1095,  1096,  1096,  1097,  1097,
    1097,  1097,  1097,  1097,  1098,  1098,  1098,  1098,  1098,  1098,
    1099,  1099,  1100,  1100,  1101,  1101,  1101,  1101,  1101,  1101,
    1102,  1102,  1103,  1103,  1104,  1104,  1104,  1104,  1104,  1104,
    1105,  1106,  1107,  1107,  1108,  1108,  1109,  1110,  1110,  1111,
    1111,  1112,  1113,  1113,  1114,  1114,  1114,  1115,  1115,  1116,
    1116,  1117,  1118,  1118,  1119,  1119
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     1,     4,     3,     4,     3,     3,
       2,     2,     1,     3,     1,     2,     2,     2,     2,     4,
       1,     1,     1,     1,     1,     1,     1,     4,     1,     3,
       3,     3,     1,     3,     3,     1,     3,     3,     1,     3,
       3,     3,     3,     1,     3,     3,     1,     3,     1,     3,
       1,     3,     1,     3,     1,     3,     1,     5,     1,     3,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     3,     1,     2,     3,     1,     2,     1,     2,
       1,     3,     1,     1,     3,     1,     1,     1,     1,     1,
       1,     1,     2,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     0,     1,     4,     5,     4,     5,
       2,     2,     1,     1,     1,     1,     2,     1,     1,     3,
       0,     1,     3,     1,     1,     2,     3,     4,     5,     2,
       1,     3,     1,     3,     1,     2,     1,     3,     3,     4,
       3,     4,     4,     1,     1,     1,     2,     2,     3,     1,
       2,     1,     3,     1,     3,     1,     3,     1,     3,     2,
       1,     1,     2,     1,     1,     2,     3,     2,     3,     3,
       4,     2,     3,     3,     4,     1,     3,     4,     1,     3,
       1,     1,     1,     1,     1,     1,     3,     3,     4,     3,
       4,     3,     2,     3,     1,     1,     1,     1,     2,     1,
       1,     2,     1,     2,     5,     7,     5,     5,     7,     6,
       7,     7,     8,     7,     8,     8,     9,     3,     2,     2,
       2,     3,     2,     3,     1,     2,     1,     1,     2,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     4,     4,
       2,     2,     2,     1,     1,     2,     2,     1,     1,     4,
       4,     4,     5,     4,     3,     3,     3,     2,     0,     2,
       2,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       3,     3,     7,     0,     1,     1,     1,     0,     1,     0,
       2,     2,     4,     0,     3,     3,     3,     4,     0,     2,
       1,     3,     3,     2,     4,     4,     5,     6,     0,     1,
       1,     2,     1,     1,     1,     1,     1,     2,     2,     1,
       2,     2,     3,     2,     2,     2,     5,     7,     7,     9,
      11,     9,     1,     4,     3,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     4,     4,     0,     3,     3,     3,
       2,     2,     2,     3,     3,     2,     2,     2,     2,     2,
       2,     5,     4,     4,     7,     3,     7,     2,     2,     2,
       6,     6,     1,     1,     2,     2,     6,     6,     6,     3,
       2,     6,     6,     3,     4,     4,     4,     5,     3,     4,
       5,     5,     5,     6,     4,     0,     1,     6,     4,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     2,     1,     2,     1,     2,     1,
       1,     1,     3,     3,     1,     1,     1,     2,     4,     2,
       2,     3,     3,     1,     2,     1,     2,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       6,     6,     6,     6,     7,     7,     7,     6,     7,     6,
       3,     4,     5,     6,     7,     6,     6,     5,     1,     1,
       2,     2,     2,     5,     0,     1,     3,     5,     5,     5,
       2,     2,     4,     4,     3,     1,     3,     3,     5,     6,
       7,     4,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     2,     2,     1,     2,     3,     3,     3,
       3,     1,     1,     4,     3,     3,     1,     1,     4,     7,
       8,     3,     1,     2,     3,     3,     3,     2,     3,     3,
       3,     3,     2,     3,     3,     3,     2,     3,     3,     3,
       2,     3,     3,     3,     3,     2,     2,     2,     3,     3,
       3,     3,     3,     3,     3,     3,     2,     2,     2,     2,
       3,     3,     3,     2,     2,     2,     3,     3,     3,     4,
       4,     4,     2,     3,     3,     3,     3,     3,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     1,     1,
       1,     3,     1,     1,     1,     0,     3,     1,     1,     4,
       8,     9,     0,     2,     0,     1,     5,     6,     3,     4,
      10,     6,     6,     6,     6,     6,     6,     6,     6,     8,
       6,     3,     5,     6,     5,     6,     5,     0,     2,     2,
       1,     1,     2,     2,     3,     1,     1,     0,     1,     1,
       1,     2,     1,     3,     0,     2,     0,     2,     3,     1,
       8,    12,     1,     0,     2,     1,     3,     3,     1,     1,
       2,     0,     2,     3,     1,     3,     5,     0,     1,     5,
       3,     4,     7,     0,     3,     3,     3,     4,     3,     6,
       7,     5,     7,     9,     3,     1,    11,     9,     7,     0,
       1,     0,     1,     2,     4,     4,     2,     1,     3,     4,
       3,     4,     2,     3,     1,     1,     1,    10,    11,    10,
      10,     9,    15,    12,     6,     6,     5,     5,     6,     8,
       5,     4,     8,    10,     8,     0,     2,     3,     2,     3,
       8,     5,     4,    15,    15,     3,     3,     3,     7,     0,
       4,     3,     1,     3,     0,     4,     3,     1,     3,     0,
       4,     3,     1,     3,     5,     3,     1,     1,     5,     6,
       7,     9,     0,     1,     0,     1,     4,     5,     1,     1,
       3,     3,     1,     2,     1,     1,     2,     2,     5,     0,
       1,     0,     1,     3,    11,     2,     3,     4,     0,     3,
       0,     4,     4,     0,     1,     1,     4,     3,     1,     5,
       0,     2,     0,     3,     0,     1,     2,     1,     2,     2,
       1,     8,    10,     7,     0,     1,     1,     2,     2,     3,
       1,     0,     3,     3,     9,     3,     1,     9,     3,     7,
       5,     3,     1,     1,     2,     1,     2,     4,     0,     1,
       2,     1,     9,     6,     2,     1,     2,     1,     3,     1,
       1,     1,     5,     6,     7,     6,     6,     4,     0,     2,
       1,     1,     3,     1,     6,     0,     1,     1,     0,     3,
       0,     1,     2,     1,     2,     3,     4,     5,     6,     2,
       6,     0,     2,     0,     2,     1,     4,     6,     7,     7,
       0,     1,     3,     0,     3,     3,     4,     2,     4,     2,
       3,     1,     4,     0,     3,     3,     3,     3,     2,     1,
       2,     0,     1,     9,     7,     8,    10,     0,     2,     1,
       0,     3,     3,     1,     1,     0,     3,     4,     3,     6,
       7,     7,     8,     4,     5,     1,     1,     6,     4,     4,
       5,     6,     6,     2,     2,     3,     6,     6,     2,     3,
       7,     6,     7,     5,     8,     5,     2,     1,     7,     3,
       1,     1,     1,     3,     1,     3,     8,     8,     1,     1,
       5,     2,     1,     3,     1,     0,     1,     1,     3,     1,
       3,     3,     5,     1,     3,     3,     1,     1,     3,    11,
       2,     1,     4,     1,     2,     2,     4,     6,     3,     1,
       0,     3,    11,     0,     3,     3,     1,     1,     1,     1,
       1,     3,     4,     1,     2,     1,     1,     3,     1,     0,
       2,     2,     3,     1,     6,     3,     1,    10,    10,     1,
       1,     3,     4,     3,     1,     2,     3,     1,     6,     3,
       1,    10,     0,     1,     0,     1,     0,     3,     0,     1,
       1,     1,     1,     0,     2,     3,     1,     3,     5,     2,
       0,     1,     2,     1,     2,     2,     3,     1,     6,     4,
       5,     7,     5,     4,     1,     5,     1,     1,     4,     1,
       5,     3,     0,     1,     1,     6,     3,     1,     5,     5,
       4,     2,     4,     3,     1,     2,     8,     0,     2,     3,
       1,     3,     1,     1,     4,     3,     1,     3,     1,     3,
       1,     3,     1,     1,     3,     1,     3,     1,     1,     1,
       3,     1,     3,     3,     1,     3,     3,     1,     2,     2,
       1,     1,     1,     1,     1,     1,     1,     1,     5,     3,
       1,     2,     4,     6,     0,     1,     2,     2,     2,     0,
       1,     4,     4,     3,     1,     1,     4,     3,     1,     3,
       1,     2,     1,     1,     3,     1,     1,     1,     1,     0,
       2,     0,     3,     3,     3,     0,     1,     3,     2,     0,
       2,     0,     3,     4,     0,     2,     4,     1,     1,     1,
       0,     3,     0,     1,     2,     3,     1,     3,     0,     1,
       1,     0,     2,     2,     8,    10,     2,     2,     3,     1,
       0,     3,     0,     2,     1,     3,     1,     3,     1,     2,
       1,     5,     6,     3,     4,     5,     6,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     3,     3,     3,     3,
       3,     3,     3,     3,     3,     3,     4,     2,     2,     3,
       3,     1,     1,     2,     2,     1,     2,     1,     2,     2,
       3,     3,     2,     2,     3,     2,     3,     2,     2,     1,
       3,     3,     3,     3,     2,     2,     3,     3,     2,     2,
       3,     3,     1,     3,     3,     1,     5,     3,     1,     1,
       1,     1,     3,     1,     3,     3,     1,     3,     3,     1,
       2,     2,     2,     1,     1,     1,     1,     1,     1,     3,
       1,     1,     1,     1,     1,     1,     8,     6,     4,     2,
       3,     1,     1,     3,     1,     1,     1,     5,     3,     1,
       0,     1,     5,     4,     2,     1,     3,     2,     0,     2,
       2,     1,     3,     6,     6,     4,     5,     5,     6,     6,
       6,     8,     7,     4,     3,     6,     2,     0,     7,     3,
       1,     1,     2,     2,     0,     6,     0,     3,     3,     1,
       1,     0,     3,     0,     5,     2,     2,     1,     2,     2,
       2,     1,     2,     2,     1,     3,     3,     1,     5,     3,
       1,     1,     8,     6,     5,     2,     4,     2,     4,     2,
       4,     1,     1,     0,     2,     3,     3,     1,     4,     0,
       1,     1,     2,     0,     1,     0,     3,     2,     1,     1,
       1,     1,     3,     1,     1,     3,     4,     3,     1,     4,
       6,     6,     8,     1,     3,     5,     1,     1,     3,     5,
       3,     5,     7,     1,     1,     3,     5,     4,     6,     7,
       7,     8,     6,     5,     2,     0,     1,     2,     1,     1,
       1,     1,     1,     2,     1,     7,     3,     5,     0,     1,
       8,     8,     1,     1,     3,     5,     3,     3,     1,     2,
       0,     1,     2,     0,     1,     2,     1,     3,     3,     3,
       1,     1,     3,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     5,     3,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     1,     3,     5,     5,     5,     7,
       7,     0,     2,     1,     4,     4,     2,     6,     7,     2,
       1,     3,     2,     1,     3,     1,     0,     2,     1,     1,
       1,     1,     4,     5,     3,    10,    11,     0,     2,     7,
       3,     5,     4,     0,     2,     3,     2,     3,     5,     3,
       2,     2,     3,     2,     4,     4,     3,     3,     3,     1,
       2,     1,     1,     1,     3,     3,     4,     4,     4,     3,
       6,     1,     1,     2,     2,     3,     4,     4,     4,     3,
       6,     7,     6,     6,     7,     6,     4,     4,     0,     2,
       3,     0,     3,     0,     2,     1,     2,     2,     2,     3,
       3,     3,     3,     6,     7,     8,     7,     4,     8,     7,
       4,     2,     2,     6,     6,     7,     8,     4,     3,     1,
       2,     4,     5,     3,     6,     0,     1,     2,     2,     4,
       4,     5,     6,     4,     2,     2,     0,     1,     2,     1,
       1,     0,     1,     2,     3,     1,     2,     1,     2,     1,
       1,     1,     1,     3,     1,     1,     0,     3,     5,     8,
       2,     4,     4,     3,     2,     3,     3,     4,     1,     1,
       2,     1,     1,     0,     2,     0,     2,     3,     1,     4,
       1,     1,     0,     1,     1,     0,     1,     1,     0,     4,
       3,     0,     4,     2,     1,     1,     1,     4,     2,     4,
       3,    10,     0,     2,     2,     3,     4,     4,     5,     2,
       2,     5,     2,     2,     3,     4,    11,     0,     2,     0,
       1,     3,     0,     1,     1,     1,     0,     1,     2,     6,
       6,     6,     5,     5,     5,     3,     1,     1,     2,     4,
       4,     4,     6,     6,     3,     3,     4,     2,     4,     4,
       3,     1,     0,     2,     2,     4,     4,     4,     6,     6,
       0,     2,     1,     1,     2,     4,     4,     4,     6,     6,
       2,     2,     0,     1,     0,     1,     2,     0,     1,     0,
       2,     3,     0,     1,     2,     2,     2,     0,     3,     3,
       1,     3,     0,     4,     1,     1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
   STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
   means the default is an error.  */
static const yytype_uint16 yydefact[] =
{
       0,     7,    98,   100,   101,   111,   110,     0,    96,   109,
     105,   106,    99,   104,   107,    97,   143,    95,   144,   108,
     113,   112,   256,   116,   117,   118,   119,   120,   121,   122,
     123,   124,   125,   126,   127,   128,   129,   130,   131,   132,
     133,     0,     0,     0,   273,   274,   277,   278,     0,     0,
     288,     0,   175,     0,     2,     4,     9,     0,    86,    88,
     114,     0,   115,     0,   164,     0,     8,   166,     6,   259,
     260,   261,   264,   265,   262,   263,   266,   267,     5,   102,
     103,     0,   159,     0,     0,   271,   270,   272,   275,   276,
       0,     0,     0,     0,   416,     0,     0,     0,     0,     0,
     287,     0,   179,   177,   176,     1,     3,    84,     0,    90,
      93,    87,    89,   142,     0,     0,   140,   229,   230,     0,
     254,     0,     0,   252,   174,   173,     0,     0,   165,     0,
     160,   162,     0,     0,     0,   290,   289,     0,     0,     0,
       0,     0,     0,     0,     0,   604,     0,   767,     0,     0,
    1172,     0,   352,     0,     0,     0,     0,   328,     0,     0,
    1172,  1172,  1172,     0,     0,     0,     0,   604,     0,  1172,
       0,     0,  1172,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   393,     0,     0,
       0,   291,     0,   292,   293,   294,   295,   296,   297,   298,
     299,     0,   355,   356,   357,     0,   358,   359,     0,   360,
     361,   362,   363,     0,     0,     0,   419,   420,     0,   506,
     505,   421,   422,   423,   424,   513,   426,   515,   427,   428,
     429,   430,   431,   456,   493,   492,   432,   646,   647,   433,
     727,   728,   481,   482,   434,   444,   440,   441,   455,   454,
     452,   453,   442,   443,   449,   438,   439,   450,   446,   445,
       0,   435,   483,   447,   448,   451,   457,   458,   459,   460,
     461,   436,   437,   484,   488,   495,   497,   499,   504,  1105,
    1098,  1099,   500,   501,  1320,  1159,  1160,  1311,     0,  1164,
    1170,   464,     0,     0,     0,     0,     0,     0,   465,   466,
     467,   468,   469,   425,   470,   471,   472,   473,   474,   476,
     475,   477,   478,     0,   479,   480,   462,     0,   463,   485,
     486,   487,   489,   490,   491,   284,   285,   286,   167,   180,
     178,    92,    85,     0,     0,   253,   134,     0,   145,   147,
     150,   148,   134,     0,   141,    93,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    11,   257,
       0,     0,     0,    30,    31,    32,    33,    34,    35,   232,
     222,    14,    24,    36,     0,    38,    42,    45,    48,    53,
      56,    58,    60,    62,    64,    66,    68,    81,     0,   224,
     225,   210,   211,   227,     0,   212,   213,   214,   215,    10,
      12,   226,   231,   255,   170,     0,   181,   183,   168,    36,
      83,     0,    10,   191,     0,   185,   187,   190,     0,   157,
       0,     0,   268,   269,     0,     0,     0,     0,   403,     0,
     408,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   343,     0,     0,   605,
     600,     0,     0,     0,  1848,  1525,     0,     0,  1527,  1065,
       0,     0,     0,     0,     0,  1810,  1529,     0,     0,     0,
     915,     0,     0,   766,   768,     0,     0,     0,   303,   518,
     519,   520,   555,   521,     0,   522,   566,   559,   567,   523,
     564,   545,   524,   525,   526,   543,  1436,   546,   527,   530,
     556,  1451,   547,   531,   532,   560,   533,   558,   534,  1434,
     565,   561,     0,   544,   535,   563,   536,   537,   550,   562,
     539,   557,  1435,   551,   552,   578,   540,   541,   542,   548,
     553,   554,   569,   579,   568,     0,   570,   538,   549,  1437,
    1438,     0,  1149,     0,     0,  1444,  1441,  1440,  1924,  1442,
    1443,  1887,  1886,     0,     0,   528,   529,  1460,     0,     0,
    1073,  1421,  1423,  1426,  1429,  1433,  1456,  1452,  1454,  1455,
     517,  1445,  1173,  1174,  1181,  1902,  1182,  1186,  1190,   517,
       0,     0,     0,     0,  1065,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1066,     0,
       0,     0,     0,   392,   380,   379,     0,   329,   333,     0,
     332,   335,   334,     0,   336,     0,   330,   509,   510,     0,
     716,   708,     0,   709,     0,   710,     0,   712,   718,   713,
     714,   715,   719,   711,     0,     0,   652,   720,     0,     0,
       0,   323,     0,     0,     0,     0,  1074,  1344,  1346,  1348,
    1350,     0,  1381,     0,   602,   601,  1178,     0,  1886,     0,
     400,     0,  1165,  1167,  1050,     0,   615,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   345,   344,   395,   394,
       0,     0,     0,     0,     0,   280,   313,   313,   281,     0,
     604,   767,     0,   604,   370,   371,   372,   505,   376,   377,
     378,     0,   283,   279,   494,   496,   498,   507,     0,     0,
     514,   516,     0,  1106,  1107,  1322,     0,  1055,  1145,     0,
    1143,  1146,     0,  1314,  1311,   388,   387,   389,  1533,  1533,
       0,     0,     0,    91,     0,   205,    94,   135,   136,   134,
     146,     0,     0,   151,   154,   138,   134,   249,     0,   248,
       0,     0,     0,     0,   250,     0,     0,    28,     0,     0,
       0,   258,     0,    25,    26,     0,   191,     0,    20,    21,
       0,     0,     0,     0,    77,    76,    74,    75,    71,    72,
      73,    78,    79,    80,    70,     0,    27,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   233,   223,   228,
       0,   172,     0,   169,     0,     0,   189,   193,   192,   194,
     171,     0,   161,   163,   158,     0,   418,     0,   409,     0,
     414,     0,   404,   406,     0,   405,  1721,     0,     0,     0,
       0,  1722,     0,     0,     0,  1729,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   590,   342,     0,     0,     0,     0,     0,     0,
       0,     0,  1047,     0,     0,   909,     0,   944,     0,   916,
       0,   645,     0,     0,  1048,     0,     0,     0,   322,   306,
     305,   304,   307,     0,     0,  1468,  1471,     0,  1432,   522,
    1459,  1486,   517,     0,     0,     0,  1517,     0,  1430,  1431,
    1924,  1924,  1928,  1897,  1925,     0,  1922,  1922,  1461,  1449,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    1175,     0,     0,     0,     0,     0,  1193,  1189,  1191,     0,
       0,  1752,  1850,  1707,  1706,     0,  1075,   805,   738,   821,
    1813,  1708,   894,  1058,   644,   806,     0,   751,  1806,  1885,
       0,     0,     0,  1023,     0,  1924,  1713,     0,     0,  1709,
       0,  1554,     0,     0,     0,   339,   338,   337,     0,   331,
     385,   717,     0,   676,   687,   694,   653,     0,   657,     0,
     670,   675,   666,   677,   662,   686,   689,   702,     0,   693,
       0,     0,     0,   688,   695,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   399,
    1349,  1149,  1378,  1377,     0,     0,     0,  1399,     0,     0,
       0,     0,     0,  1385,  1382,  1387,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,  1179,  1180,
       0,     0,     0,     0,   606,     0,     0,  1942,  1190,     0,
       0,     0,     0,     0,   808,     0,     0,   800,     0,     0,
    1169,   511,   512,   366,   366,   368,   369,   374,  1901,   354,
       0,   373,     0,   301,   300,     0,     0,     0,     0,   282,
       0,     0,     0,     0,  1323,   503,  1322,     0,   502,     0,
       0,  1144,  1163,     0,  1161,  1314,     0,     0,     0,  1531,
    1532,     0,  1822,  1821,     0,     0,     0,   208,     0,   137,
     155,   153,   149,     0,     0,   139,     0,   219,   221,     0,
       0,     0,   247,   251,     0,     0,     0,     0,    13,     0,
     193,     0,    19,    16,     0,    22,     0,    18,    69,    39,
      40,    41,    43,    44,    47,    46,    51,    52,    49,    50,
      54,    55,    57,    59,    61,    63,    65,     0,    82,   216,
     217,   182,   184,   201,     0,     0,   197,     0,   195,     0,
       0,   186,   188,     0,     0,     0,   410,   412,     0,   411,
     407,     0,     0,     0,  1736,     0,  1737,  1738,     0,  1068,
    1069,     0,  1745,  1727,  1728,  1705,  1704,   835,   887,   886,
     836,     0,   834,   824,   827,     0,   825,     0,     0,     0,
       0,   988,     0,   892,     0,     0,   892,     0,     0,     0,
       0,     0,     0,     0,   855,   851,  1846,  1845,  1844,  1812,
       0,     0,     0,     0,     0,     0,   621,   632,   631,   628,
     629,   630,   635,  1057,   899,     0,     0,   898,   896,   902,
       0,     0,     0,   783,     0,   797,   791,     0,     0,     0,
       0,     0,     0,  1799,  1800,  1760,  1757,     0,     0,     0,
       0,   591,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   917,  1849,  1526,  1528,  1811,  1530,  1049,     0,     0,
       0,   910,   911,     0,     0,     0,     0,     0,     0,   988,
     968,   951,   946,   965,   945,   950,     0,     0,  1050,     0,
    1711,  1712,     0,   774,  1050,     0,   308,     0,     0,     0,
    1468,  1465,     0,     0,  1470,     0,     0,  1450,   517,  1150,
    1153,  1050,  1172,  1521,  1314,  1520,  1453,     0,  1924,  1894,
    1895,  1926,  1923,  1927,     0,  1927,  1484,     0,  1439,  1422,
    1424,  1425,  1427,  1428,     0,     0,  1494,     0,     0,  1550,
       0,   572,   574,   573,   575,   529,   577,  1460,     0,   517,
    1190,  1924,     0,     0,  1903,     0,  1342,  1185,  1194,  1192,
    1187,   517,  1063,   739,   822,   807,   895,   643,  1865,     0,
    1767,     0,     0,     0,     0,     0,     0,  1924,     0,     0,
     383,   382,  1920,     0,     0,     0,  1553,  1710,  1551,     0,
       0,     0,   340,   341,     0,     0,   659,   672,   679,   664,
     655,     0,   706,   696,   658,   671,   678,   663,   690,   654,
       0,   705,   667,   698,   680,   697,   660,   673,   668,   681,
     665,   691,   703,   656,     0,   707,   669,   661,   692,   704,
     682,   674,   684,   685,   683,     0,     0,   724,   648,   722,
     723,   651,     0,     0,  1087,  1023,  1942,  1942,   325,   324,
    1345,  1347,  1379,  1380,     0,  1375,  1353,  1392,     0,     0,
       0,  1384,  1393,  1404,  1405,  1386,  1383,  1389,  1397,  1398,
    1395,  1408,  1409,  1388,  1357,  1358,  1359,  1360,  1361,  1362,
    1261,  1266,  1267,  1149,  1263,  1262,  1264,  1265,  1418,  1420,
    1363,  1415,   517,  1419,  1364,  1365,  1366,  1367,  1368,  1369,
    1370,  1371,  1372,  1373,  1374,   729,     0,     0,     0,     0,
    1910,  1718,  1717,     0,   611,   610,  1716,     0,     0,     0,
    1139,  1140,  1311,     0,  1148,  1156,     0,  1078,     0,  1166,
    1054,     0,  1053,     0,   801,   616,     0,     0,     0,     0,
       0,   951,     0,   364,   365,     0,   508,     0,   318,     0,
    1047,     0,   353,     0,  1324,  1321,     0,  1312,  1326,  1328,
       0,  1317,  1318,  1319,  1315,  1162,  1534,     0,  1537,  1539,
       0,  1585,     0,  1543,     0,  1594,     0,  1819,  1818,  1823,
    1814,  1847,     0,   206,   152,   156,   218,   220,     0,     0,
       0,     0,    29,     0,     0,     0,    37,    17,     0,    15,
       0,   202,   196,   198,   203,     0,   199,     0,   417,   402,
     401,   413,     0,     0,     0,  1743,     0,  1741,     0,  1070,
       0,     0,  1748,     0,  1746,  1747,     0,     0,     0,   832,
     826,     0,     0,     0,     0,     0,   607,     0,   893,     0,
       0,   879,     0,   888,     0,     0,     0,     0,     0,   858,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   850,     0,     0,     0,     0,   846,     0,     0,   847,
       0,   634,   633,     0,     0,     0,   636,     0,     0,   897,
       0,   905,   904,     0,   903,     0,  1861,     0,     0,     0,
       0,   785,     0,   756,     0,     0,     0,     0,     0,     0,
     798,   752,     0,     0,   789,   788,   791,   754,     0,     0,
    1761,     0,  1762,     0,   598,   599,   592,     0,     0,  1875,
    1874,     0,     0,     0,     0,  1882,  1883,  1884,   597,     0,
       0,     0,   608,   346,     0,     0,     0,     0,     0,     0,
    1048,     0,     0,   995,  1013,     0,   993,   908,   912,   736,
       0,     0,  1935,  1936,  1934,  1040,   966,     0,   979,   980,
     981,     0,     0,   969,   971,     0,     0,   948,   964,   947,
       0,     0,   944,  1775,  1786,  1769,     0,     0,   776,     0,
       0,   309,     0,  1472,     0,  1464,     0,  1469,  1463,     0,
    1458,   517,     0,     0,  1178,     0,     0,  1516,  1896,  1898,
    1921,  1899,  1483,     0,     0,     0,     0,  1475,  1494,  1487,
    1559,  1448,     0,     0,     0,  1342,  1904,  1922,  1922,     0,
    1101,  1102,  1104,     0,  1100,     0,   823,   732,  1064,     0,
       0,  1031,     0,     0,   375,  1888,  1922,  1922,     0,     0,
       0,     0,  1555,     0,  1714,  1554,  1715,   326,     0,   700,
     699,   701,     0,     0,     0,  1130,  1086,  1085,     0,     0,
       0,  1083,  1190,  1023,  1376,     0,  1354,     0,     0,  1391,
    1402,  1403,  1394,  1406,  1407,  1390,  1400,  1401,  1396,  1410,
    1411,     0,     0,     0,     0,   603,   609,     0,     0,     0,
     614,  1151,     0,  1079,     0,  1314,  1311,     0,     0,  1051,
       0,     0,     0,     0,  1339,     0,     0,     0,     0,     0,
     819,     0,  1900,   314,     0,     0,   316,   315,     0,   381,
       0,  1056,     0,  1329,  1330,  1331,  1313,     0,  1535,     0,
    1540,  1541,     0,     0,     0,  1573,  1574,     0,  1543,     0,
    1586,  1588,  1589,  1590,  1591,  1592,  1598,     0,  1524,  1544,
    1584,  1593,  1825,     0,  1820,     0,   207,   209,     0,     0,
       0,     0,     0,     0,   236,   237,   234,    23,    67,   204,
     200,  1732,  1730,     0,     0,  1733,  1739,     0,  1735,     0,
    1749,  1750,  1751,     0,   828,     0,   830,   833,   913,  1071,
    1072,   582,   581,   580,   583,   587,   398,   589,     0,   397,
     396,   989,  1929,     0,   857,   988,     0,     0,     0,     0,
       0,   848,     0,   874,     0,     0,   867,   889,     0,   859,
     894,     0,   844,   866,     0,     0,     0,     0,     0,     0,
     845,   865,   856,   639,   638,   642,   641,   640,   637,   900,
     901,   907,   906,     0,  1862,  1863,     0,   782,   741,     0,
     743,   772,   742,   744,     0,   784,   748,   766,   746,   750,
       0,   745,   747,     0,   753,   792,   794,     0,   790,     0,
     755,     0,  1763,  1805,  1764,  1804,     0,     0,   593,   596,
     595,  1878,  1881,  1880,     0,  1879,  1077,   617,  1076,     0,
       0,  1775,     0,  1059,     0,  1795,  1719,     0,  1720,     0,
       0,  1050,   737,   997,   996,   998,   995,  1020,  1015,  1041,
       0,     0,     0,   944,   988,     0,     0,     0,   970,     0,
       0,   949,  1791,   619,   968,  1775,  1770,  1776,     0,     0,
       0,  1753,  1787,  1789,  1790,     0,   775,     0,   757,     0,
       0,     0,     0,     0,  1467,  1466,  1462,     0,     0,  1152,
       0,     0,  1519,  1518,  1494,  1494,  1494,  1496,  1477,     0,
    1494,     0,  1476,     0,     0,  1460,     0,   517,  1314,  1927,
    1927,  1924,     0,     0,     0,  1343,  1188,     0,     0,  1807,
       0,     0,  1024,     0,     0,  1927,  1927,  1924,     0,     0,
     390,   391,   576,   571,  1556,   327,     0,   725,   721,     0,
       0,  1081,     0,     0,     0,     0,  1355,     0,     0,  1351,
    1414,  1417,   517,     0,   732,  1912,  1913,     0,     0,  1924,
    1911,     0,  1342,   612,   613,  1155,  1147,  1141,  1314,     0,
       0,  1113,  1342,  1109,     0,   517,  1052,     0,   803,  1336,
       0,  1337,  1322,     0,     0,   809,     0,   968,   820,   367,
     319,   320,   317,     0,     0,  1328,  1325,     0,  1327,  1316,
    1536,  1542,  1545,     0,  1585,     0,     0,  1533,  1523,     0,
    1587,     0,  1599,     0,     0,     0,  1838,  1824,  1815,  1816,
    1823,     0,   239,     0,     0,     0,     0,     0,     0,     0,
    1731,  1744,  1740,     0,  1734,   829,   831,   586,   585,   588,
     584,     0,   968,   885,     0,   991,     0,   990,     0,     0,
    1328,     0,     0,   920,     0,     0,   869,     0,     0,     0,
       0,   890,  1328,     0,     0,     0,     0,   862,     0,     0,
       0,  1860,  1859,  1864,     0,     0,   771,   786,     0,     0,
       0,     0,   787,  1801,  1802,     0,  1765,  1759,     0,     0,
     594,  1871,     0,   347,   348,  1775,  1754,     0,  1061,  1796,
       0,     0,     0,  1723,     0,  1724,     0,     0,     0,   998,
       0,  1014,  1021,     0,  1042,  1044,   992,   967,     0,   968,
     978,     0,     0,   943,   953,   952,  1756,  1792,   620,   623,
     627,   624,   625,   626,  1852,  1777,  1778,  1775,     0,  1773,
       0,  1797,  1793,  1768,  1788,  1867,   777,     0,     0,  1055,
    1060,     0,   311,   310,   302,  1485,  1457,     0,  1183,  1478,
    1479,  1480,     0,  1501,     0,  1473,  1561,  1474,  1560,  1447,
       0,     0,  1080,  1906,  1907,  1905,  1922,  1922,  1103,   732,
     733,   384,   386,  1030,  1092,     0,  1090,  1091,  1889,  1890,
    1891,  1922,  1922,     0,   725,     0,   649,  1129,     0,     0,
    1024,     0,  1082,  1094,     0,     0,  1356,  1352,     0,   732,
     734,  1922,  1922,  1914,     0,     0,     0,     0,     0,  1195,
    1197,  1206,  1204,  1942,  1301,  1142,  1943,  1117,     0,  1116,
     517,     0,  1314,     0,     0,  1168,     0,   802,  1338,  1340,
       0,     0,     0,   812,     0,   923,     0,  1027,  1332,  1333,
       0,     0,  1538,  1570,  1568,  1543,     0,     0,  1575,     0,
       0,     0,     0,     0,   604,     0,  1585,  1543,     0,     0,
       0,     0,     0,     0,     0,     0,   604,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  1320,  1654,  1566,     0,  1636,  1610,  1624,  1625,  1640,
       0,  1626,  1629,  1631,  1632,  1633,  1543,  1679,  1678,  1680,
    1681,  1627,  1628,  1630,  1634,  1635,  1637,  1638,  1639,  1554,
    1596,  1545,     0,     0,  1831,  1830,  1826,  1828,  1832,     0,
       0,  1817,   238,   240,   241,     0,   243,     0,     0,     0,
     235,  1742,  1930,  1932,     0,   882,     0,   968,   987,     0,
     920,   920,   920,     0,     0,   932,   874,     0,     0,   852,
       0,     0,     0,     0,     0,     0,     0,  1029,   894,     0,
       0,     0,     0,   849,   854,   861,     0,   773,   765,   749,
       0,   793,   795,  1766,  1803,  1758,   618,     0,     0,  1755,
       0,  1725,     0,     0,     0,  1041,  1011,     0,     0,     0,
     941,     0,     0,   622,     0,     0,     0,     0,  1775,  1771,
    1794,  1798,     0,  1869,     0,     0,   761,   758,   760,     0,
    1045,  1062,     0,     0,     0,     0,     0,     0,     0,  1503,
       0,     0,  1482,     0,  1460,  1927,  1927,  1808,  1097,     0,
    1927,  1927,   571,   650,     0,  1131,     0,     0,  1084,     0,
       0,  1274,  1133,  1416,   734,   735,   730,  1927,  1927,     0,
       0,  1924,     0,     0,     0,     0,     0,  1279,  1275,  1279,
    1279,     0,     0,     0,     0,  1212,     0,     0,     0,  1176,
       0,  1309,     0,     0,     0,  1108,  1096,  1111,  1110,  1114,
       0,     0,  1334,  1322,     0,     0,   321,   925,   918,   924,
    1328,  1547,     0,  1522,  1577,     0,     0,     0,     0,     0,
    1610,     0,  1548,     0,  1676,  1670,     0,   600,  1703,     0,
    1693,     0,     0,  1567,     0,  1549,     0,     0,  1696,     0,
    1554,  1701,     0,   602,     0,  1563,     0,  1700,     0,  1621,
       0,  1651,  1650,  1652,  1649,  1645,  1643,  1644,  1648,  1646,
    1647,     0,     0,  1613,     0,  1611,  1623,  1653,     0,     0,
       0,     0,     0,     0,  1833,  1834,  1835,     0,  1585,  1809,
     242,   244,   245,     0,  1931,  1933,   880,     0,     0,  1937,
       0,   932,   932,   932,  1025,     0,     0,   982,   869,     0,
     877,     0,     0,     0,     0,     0,     0,   841,     0,   894,
     891,  1328,     0,     0,   962,   963,     0,     0,     0,   799,
       0,   351,   349,     0,  1726,  1055,   999,  1043,     0,   988,
    1022,  1016,     0,     0,     0,     0,   977,     0,   975,     0,
    1853,  1854,     0,  1783,  1780,  1797,  1779,  1775,  1772,  1868,
    1872,  1870,   762,   763,   759,   770,     0,   769,   312,  1154,
    1184,  1558,  1342,  1342,  1500,  1497,  1499,     0,     0,     0,
       0,  1562,  1481,  1446,  1908,  1909,  1089,  1892,  1893,   726,
    1128,     0,  1095,  1093,     0,     0,  1342,   731,  1916,  1917,
    1922,  1922,  1915,     0,  1886,     0,  1207,     0,     0,     0,
    1212,  1196,  1280,  1278,  1276,  1277,     0,  1190,     0,  1270,
    1942,  1942,     0,  1227,  1190,  1213,  1214,     0,     0,  1308,
       0,  1299,  1309,     0,  1305,     0,  1115,  1118,   804,     0,
    1340,   811,     0,     0,     0,   920,  1026,  1546,     0,     0,
       0,  1571,  1569,     0,  1576,  1320,     0,     0,     0,     0,
    1676,  1673,     0,     0,  1669,     0,  1690,     0,     0,     0,
       0,     0,  1945,  1944,     0,  1695,     0,  1661,     0,  1697,
       0,  1702,     0,     0,  1543,  1699,     0,     0,  1642,     0,
       0,  1612,  1614,  1616,  1583,  1684,  1564,  1655,   517,  1597,
    1602,     0,  1603,     0,     0,  1608,  1827,  1836,     0,  1841,
    1840,  1843,   246,   881,   883,     0,   837,     0,   985,   986,
     983,     0,   934,   868,   875,     0,     0,     0,     0,   872,
       0,     0,   839,   840,     0,   853,  1028,   879,     0,     0,
       0,     0,     0,   764,   796,     0,  1067,  1046,  1012,     0,
     994,   988,  1003,     0,     0,     0,     0,   942,   976,   973,
     974,     0,     0,  1855,  1851,  1798,  1781,  1774,  1876,  1873,
     740,   779,     0,  1301,  1301,     0,  1502,  1507,     0,  1514,
       0,  1505,     0,  1495,     0,  1088,     0,  1138,     0,  1136,
    1137,  1314,  1927,  1927,     0,  1190,     0,     0,  1190,  1190,
    1274,  1203,  1190,     0,     0,  1271,  1212,     0,     0,     0,
    1199,  1307,  1304,     0,     0,  1171,  1302,  1310,  1306,  1303,
    1112,  1341,  1335,     0,     0,     0,     0,   928,     0,   934,
       0,     0,  1578,     0,     0,     0,  1543,  1671,  1675,     0,
       0,  1672,  1677,     0,     0,  1610,  1694,  1692,     0,     0,
       0,     0,     0,   517,  1666,     0,     0,     0,     0,  1663,
    1682,     0,     0,   517,     0,  1622,     0,     0,     0,     0,
    1620,  1615,     0,     0,     0,     0,  1609,     0,     0,  1829,
    1837,     0,  1839,     0,     0,     0,  1940,     0,   984,   922,
     921,     0,   940,     0,   933,   935,   937,   876,   878,     0,
     870,     0,  1937,     0,   838,   860,     0,   961,     0,     0,
       0,   350,     0,     0,     0,  1004,     0,  1328,  1009,  1002,
       0,     0,  1017,     0,     0,   956,     0,  1856,  1857,  1784,
    1782,  1785,  1866,  1877,     0,  1557,  1176,  1176,  1498,     0,
    1506,     0,  1508,  1509,  1491,     0,  1490,     0,  1119,  1121,
    1134,     0,  1132,  1918,  1919,     0,  1205,  1211,   517,     0,
    1202,  1200,     0,  1268,  1269,  1942,  1190,     0,     0,  1217,
    1228,     0,     0,     0,     0,  1296,  1297,  1177,  1295,  1298,
    1300,   810,     0,     0,   815,     0,   926,     0,   919,   914,
    1579,  1580,  1572,  1595,     0,  1674,     0,     0,  1691,     0,
    1658,     0,     0,     0,  1543,     0,  1662,     0,     0,     0,
    1698,  1657,  1683,  1641,  1656,  1618,  1617,     0,  1565,     0,
    1601,  1604,  1600,  1607,     0,   884,     0,  1938,     0,  1023,
     939,   938,   936,   873,   871,   843,     0,     0,     0,     0,
       0,     0,  1328,  1005,  1328,   920,  1018,  1019,  1929,   954,
       0,     0,  1858,  1784,   778,  1299,  1299,     0,  1515,  1492,
    1493,  1488,     0,     0,  1123,     0,  1120,  1135,  1208,     0,
    1190,  1273,  1272,  1198,     0,     0,     0,     0,     0,  1233,
       0,  1230,     0,     0,     0,     0,     0,   813,     0,     0,
     927,  1582,     0,  1667,  1543,     0,     0,  1687,     0,  1494,
       0,  1661,  1661,     0,  1619,  1606,     0,     0,  1941,  1939,
    1033,     0,   879,   879,     0,   780,  1006,   920,   920,   932,
       0,   958,   955,   972,  1157,  1158,  1511,     0,  1504,     0,
    1489,  1124,  1125,     0,  1210,   517,  1201,     0,     0,     0,
    1221,  1216,     0,     0,     0,  1232,     0,     0,  1284,  1285,
       0,  1149,  1292,     0,  1290,  1288,  1293,  1294,     0,   814,
     930,  1668,     0,  1659,  1687,     0,     0,  1689,  1487,  1665,
    1664,  1660,  1605,  1842,     0,  1032,  1937,     0,     0,     0,
     932,   932,  1007,  1929,     0,     0,  1510,  1512,  1513,  1130,
       0,  1122,  1190,  1190,     0,     0,  1215,  1229,     0,     0,
    1282,     0,  1281,  1291,  1286,     0,     0,     0,   929,  1581,
       0,  1688,  1543,     0,     0,     0,   842,     0,     0,     0,
    1010,  1008,   960,     0,     0,     0,     0,  1219,  1218,  1220,
       0,     0,     0,  1224,  1190,  1260,  1231,     0,     0,  1283,
    1289,  1287,     0,   931,  1543,     0,  1037,  1039,     0,  1036,
    1034,  1035,   879,   879,     0,     0,  1929,     0,  1314,  1258,
    1259,  1222,     0,  1225,     0,  1226,     0,     0,  1685,  1038,
       0,     0,   781,     0,   959,     0,  1126,  1223,     0,  1243,
       0,  1236,  1238,  1240,   818,     0,     0,  1686,   863,   864,
    1929,     0,     0,  1242,  1234,     0,     0,     0,     0,   957,
    1127,  1239,     0,  1235,     0,  1237,  1245,  1248,  1249,  1251,
    1254,  1257,     0,   817,  1241,     0,  1247,     0,     0,     0,
       0,     0,     0,  1244,     0,  1250,  1252,  1253,  1255,  1256,
     816,  1246
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int16 yydefgoto[] =
{
      -1,    53,    54,    55,   371,   372,  1154,   373,   374,   375,
     376,   377,   378,   379,   380,   381,   382,   383,   384,   385,
     386,   387,   785,   388,   411,    56,   119,   108,   333,   109,
      58,   102,   738,    60,   114,   115,    61,   337,   338,   339,
     742,  1133,   743,    62,   129,   130,    63,    64,   126,   127,
      65,   413,   405,   406,  1184,   415,   416,   417,   818,   819,
     736,  1128,   390,   391,   392,   393,   394,   121,   122,   395,
     396,   397,   398,    66,   123,   412,   400,   341,    69,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    96,   190,
     191,   192,   892,  1337,  2183,  1093,  1957,  2290,   193,   194,
     195,   615,   616,   976,   196,   197,   198,   199,   200,   201,
     202,  1583,   203,   204,   205,   206,  1420,   207,   208,   209,
     210,   211,   212,   213,   606,   214,    97,    98,    99,   100,
     215,   216,   217,   218,   219,   697,   221,   222,   557,  1388,
     558,   223,   224,  1756,  2581,  2582,  2583,   450,  2584,   229,
     230,  1676,  1067,  1292,   231,   232,  2428,  2429,  1256,  2430,
    1258,  1259,  2431,  2432,  2433,  2077,   233,   234,   235,   236,
     237,   238,   635,   636,  1478,  1479,  2496,   239,   240,   241,
    2219,  2756,   242,   243,   244,  2448,  2717,  2718,  2679,   474,
     475,  2946,  2090,  2091,  1818,  2178,  3150,  2088,  1733,  1746,
    1747,  2105,  2106,  1741,   245,   246,   247,  2537,   248,   249,
     250,   251,   252,  1948,   253,  1581,  3363,  3364,  2287,  1405,
     254,  1223,  1224,   255,  1709,  1245,  2659,  3108,  3109,  2356,
    2889,  2890,  2044,  2644,  2645,  1681,  1225,   256,  1682,  1407,
     257,  1268,  1269,  1724,   258,  1312,  1787,  1226,   259,   260,
    3025,  2655,  2798,  2799,  3206,  3207,  3588,  2887,  3274,  3275,
    3276,   261,  1320,  1807,  1321,  3304,  3305,  2903,  2904,  1322,
    1323,  1802,  1803,  1804,  2927,  2928,  1797,  1798,  1799,  1684,
    2346,  1785,  1786,  2145,  2408,  3130,  3131,  3132,  2919,  2146,
    2147,  2411,  2412,  1415,  2353,  2294,  2363,  1872,  3268,  3555,
    3629,  1324,  2415,   262,   263,   264,   476,  1071,  1571,  1572,
    1108,   265,   266,   267,   268,   477,  1777,   269,   270,   271,
     272,   273,   274,  1068,  2585,  2586,  1483,  1484,  2485,  2486,
    2502,  2503,  2587,  2588,   279,   280,   281,  1396,  1860,  1861,
     715,  2272,  2273,  2274,  2528,  2529,  2589,  3328,  3329,  3445,
    3571,  2498,  2240,  2590,  2976,  3168,  3169,  2591,  1560,  1561,
     722,  1562,   905,  1563,  1349,  1350,  1564,  1565,   284,   285,
     286,   287,   288,   662,   663,   289,   290,   573,   931,  3011,
    1060,   575,  2725,   576,   577,   937,  2262,  2519,  2520,  2985,
    3004,  3005,  3348,  3349,  3457,  3523,  3612,  3613,  3006,  3189,
    3460,  3524,  3461,  3618,  3660,  3661,  3662,  3672,  3663,  3685,
    3695,  3686,  3687,  3688,  3689,  3690,  3691,  1529,  2521,  2998,
    2999,  2522,  2771,  2993,  3355,  3527,  3528,  3356,  3533,  3534,
    3535,  3357,  3358,  3195,  2779,  2780,  3199,  2781,  3014,   723,
    1114,  1604,   717,  1105,  1597,  1598,  1965,  2298,   291,  1945,
    2792,  1864,   906,   647,   648,   649,   650,  1036,  1037,  1038,
    1039,  1040,  1041,  1042,  1043,  1044,  1045,  1046,  1047,  1048,
    1049,  1050,  1051,  1052,  1053,   559,  1530,   652,   561,   562,
     563,   564,   565,   901,   919,   566,  1340,  1341,  1823,  1343,
     895,   896,   567,  2200,  3325,  3326,  1847,  2463,  2955,  2956,
    2729,  2959,  3161,  3508,  3162,   907,   568,  1354,  1355,   292,
     293,   294,   295,   296,   297,  1121,  1117,  1607,  1608,  1972,
    1988,  2552,  2813,  2826,  1380,  1427,  2592,  2950,   569,  2594,
    2822,  1974,  1975,  2595,  1978,  1613,  1979,  1980,  1981,  1614,
    1982,  1983,  1984,  2313,  1985,  3081,  3254,  3084,  3085,  2854,
    2855,  3071,  3072,  3073,  3249,  2838,  2596,  2597,  2598,  2599,
    2600,  2601,  2602,  2603,  3238,  3239,  3057,  2604,  2814,  2815,
    3040,  3041,  3219,  3043,  2605,  2606,  2607,  2608,  2609,  3546,
    2610,  2611,  2612,  3049,  2613,  2614,  2615,  2616,  2617,  2618,
     298,   299,   300,   301,   302,   967,   968,  1332,   969,   970,
     303,  1300,   304,   845,  2138,  2139,  2140,   305,  1657,  2018,
    2015,  1213,  1214,   306,   307,   308,   309,  1285,   310,   311,
    1814,  1815,  2166,  2167,  3146,  2171,  2172,  2426,  2173,  2174,
    2136,  3311,  1286,  2387,  2114,  2115,  1410,   312,   313,   314,
     315,  1124,  1620,  1125,  1994,  2316,  2626,  2627,  2628,  2866,
    3088,  3259,  2630,  3262,  2869,  1249,   316,   317,   318,   319,
    2705,  2085,   320,  1726,   321,   322,  2713,  2940,  1765,  3148,
    1766,  3312,  1767,   323,   324,   570,  1421,   571,  1089,   933,
    1394,  1928,  2259,  2260,   972,  1363,  1364,   913,   914,   915,
    2342,  2343,  2874,  1325,  3096,  3265,  3266,  1567,  3054
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
#define YYPACT_NINF -3137
static const yytype_int16 yypact[] =
{
    4825, -3137, -3137,   567,   625, -3137, -3137,    87, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  2007,   183,  1030, -3137, -3137, -3137, -3137,  1141,  1273,
     241,    99,  5339,  4698, -3137, -3137, -3137,   162, 14676, 14676,
   -3137,    88, -3137,  3565,  1837,   105, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  1290,  1017,  1369,  1456, -3137, -3137, -3137, -3137, -3137,
    1100,  1380,  1474,  1299, -3137,   -14,  5979,  1333,  1377,  1516,
   -3137,  1272, -3137, -3137,  5339, -3137, -3137, -3137,  1281, -3137,
    2144, -3137, -3137, -3137,  4198,  4376,  1355, -3137, -3137,   162,
   -3137,  3780,  3565, -3137,    94,  1390,  1938, 14827,  1837,  -136,
   -3137,  1418,  1290,  1815,  1914, -3137, -3137,  1762,  1818,  1703,
    1736,    19,  1585,   965,  1910,  1851,  1790,  2370,  1808, 11834,
    1892,  9986, -3137,  2604,   800,  2077,    46,   848,  1592,  2819,
    1892,  1892,  1892,  1811,  2046,  9458,  2819,  1851,  1591,  1892,
      34,  2119,  1892,  1591,  1591,  2045,  2054,  2068,  2086,  2089,
    2111,   694,  2120,  1946,  2002,  2157,  1375,  2020,  2003,  2050,
    2084, -3137,   764, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  2090, -3137, -3137, -3137, 14029, -3137, -3137, 14110, -3137,
   -3137, -3137, -3137,  2110,  2098,  2104, -3137, -3137,  1021,    23,
      59, -3137, -3137, -3137, -3137,  2069, -3137,  2080, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
    1591, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,  1282,
   -3137, -3137, -3137, -3137,  2321, -3137, -3137,  1397,   694, -3137,
   -3137, -3137,  2148,  2155,  2165,  1591,  1591,  1591, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,  1591, -3137, -3137, -3137,  1591, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,    99,   619, -3137,  2436,  4494, -3137, -3137,
    3901, -3137,  2436,  4583, -3137,  2103,  2108,  1938,  2130,  2134,
    3485,  2162,  1290,  1068,  2377,  2178,  2180,  2183, -3137,  2521,
    2395,  2395,  4917, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137,   210,   132,  1938, -3137,  1636,  1749,  1934,   107,
    2070,  2176,  2168,  2171,  2527,    69, -3137, -3137,  1286, -3137,
   -3137, -3137, -3137, -3137,  4015, -3137, -3137, -3137, -3137,  2175,
   -3137, -3137, -3137, -3137, -3137,  2186,  2184, -3137, -3137, -3137,
   -3137,  2192, -3137,  5067,  2195,  2193, -3137, -3137,  1290, -3137,
    1938,   822, -3137, -3137,  2485,  2249,  2250,   259, -3137,  2238,
   -3137,    76,  1371,  1591,  1591,  1591,   554,  1591,  1591,  1591,
    1591,  1591,  2340,  1591,  1591,    40, -3137,  2241,   808, -3137,
    2242,  2324,  2294,   904, -3137, -3137,  2358,  2325, -3137,  2375,
    1591,  1591,  1591,  1591,  2304, -3137, -3137,  2335,  1591,  1591,
   -3137,  2362,  1591,   306, -3137,  2314,  2366,  2493,   845, -3137,
   -3137, -3137, -3137, -3137, 10250,  2292, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, 12098, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, 13908, -3137, -3137, -3137, -3137,
   -3137,  2285,  7610, 12098, 12098, -3137, -3137, -3137,    -3, -3137,
   -3137, -3137, -3137,  2276,  2277, -3137, -3137,  2283,  2300,  2303,
   -3137,  2305,  2107,  1706, -3137, -3137, -3137, -3137, -3137, -3137,
    1628, -3137, -3137,  2474, -3137,  2462,  2299, -3137,    42,  1633,
    1145,  1591,  1591,  1591,  2403,  1591,  1591,  1591,  1591,  1591,
    1591,  1591,  1591,  1591,  1591,  2387,  1591,  1591,  2288,  2516,
    2392,  2297,  1591, -3137,  2398, -3137,  1763, -3137, -3137,  1427,
   -3137, -3137, -3137,  1427, -3137,  2298,  2494, -3137, -3137,  1482,
    2445,    90,  2477,  2566,   478,  2568,  2570,  2571, -3137, -3137,
    2573,  2575, -3137, -3137,  2576,   663, -3137, -3137,   131,  2506,
    2507,  2431,  2332,  9722,  2353,  2353, -3137,  2487,  2599, -3137,
   -3137,  2369,  1268,   650,   -31, -3137,   150,  2356,  1140,  2359,
   -3137,  1340,  2365, -3137,  2373,  2468,  2371,  1591,  1591,  1591,
    1591,  1591,  1591,   672,  1822,  1653, -3137, -3137, -3137, -3137,
    1667,  2360,  2363,  2374,  2556, -3137,  2559,  2559, -3137,  2941,
    1851,  4117,  1870,  1851, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  2378, -3137, -3137, -3137, -3137, -3137, -3137,  2364,  2457,
   -3137, -3137,  2524, -3137, -3137,   885,  2475,  2464, -3137,    47,
    2629, -3137,   694,  2545,  1397, -3137, -3137, -3137,  2399,  2399,
     146,   906,  2626, -3137,   619, -3137, -3137, -3137, -3137,  2436,
   -3137,  1938,  1331, -3137,  2326, -3137,  2436, -3137,  2327, -3137,
    2295,  2706,  1260,  2323, -3137,  1344,  4917, -3137,  1938,  1938,
    1938, -3137,  1938, -3137, -3137,  1826,  5266,  2346, -3137, -3137,
    1290,   960,  1938,  1290, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137,  1938, -3137,  1938,  1938,  1938,
    1938,  1938,  1938,  1938,  1938,  1938,  1938,  1938,  1938,  1938,
    1938,  1938,  1938,  1938,  1938,  1938,  1938, -3137, -3137, -3137,
    2295, -3137,  2344, -3137,  4990,  1683, -3137,   126, -3137,  1993,
   -3137, 14754, -3137, -3137, -3137,  2385, -3137,    70, -3137,  2386,
   -3137,   420, -3137, -3137,  2411, -3137, -3137,   511,  2390,  2391,
    2394, -3137,  2618,  2396,   639, -3137,   -28,  2630,  2633,   926,
    2625,   -64,  2376,  1543,  1116,  2635,     7,  1591,    84,   772,
    2401,  2405,   442, -3137,  1591,  1591,  2632,  2653,  1591,  1591,
    2410,  2491,   717,  1591,  2439,    56,  2614,   875,  1591, -3137,
    2496, -3137,  1591,  2425,  2182,  1591,  1591,  2511, -3137, -3137,
   -3137, -3137,  2400,  9458,  2526,   781, -3137,  9458, -3137, -3137,
   -3137, -3137,  2444, 13908,  1591,  2561, -3137,  1711, -3137, -3137,
     -17,   871, -3137, -3137, -3137,  2438,  2412,  2412, -3137, -3137,
    7874,  2484, 11834, 11834, 11834, 11834, 11834,  6814,  9458,  6611,
   -3137,  1340,  1483,  2638, 11834, 12830, -3137, -3137, -3137,  6185,
    1591, -3137, -3137, -3137, -3137,  1591, -3137, -3137, -3137,  2688,
   -3137, -3137,  2689, -3137, -3137, -3137,  1591, -3137,  2446, -3137,
    2533,  2646,  2647,  2476,   465,   871, -3137,  2466,  2467, -3137,
     434,   -72,  2465,  2460,  2461, -3137, -3137, -3137,   459, -3137,
   -3137, -3137,  1267, -3137, -3137, -3137, -3137,  1193, -3137,  2577,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,  2558, -3137,
    2578,  1055,  2583, -3137, -3137,  2610,    26,  2586,  1594,  2587,
    2588,   282,    14,  2819,  2652,  1340,  1591,  1591,   465, -3137,
   -3137,  2569, -3137, -3137,  9458,  9458,   -73, -3137,  2227, 11834,
     909, 11834,  2483,    92,   976,   231, 11834, 11834, 11834, 11834,
   11834, 11834, 12310, 12310, 12310, 12310, 12310, 12310, 12310, 12310,
   12310, 12310, 12310, 12310,    14,   383,  2603,  2701, -3137, -3137,
    9986,  1431,  2651,   780, -3137,  1591,    -9,  2628,    42,  1591,
   13908,  2731,  1591,  1591, -3137,  2595,   418, -3137,  2505,  2637,
   -3137, -3137, -3137,  2579,  2579, -3137, -3137, -3137, -3137,  2500,
    2492, -3137,  1011, -3137, -3137,   583,  2242,  2560,  2495, -3137,
    2598,  2363,  1591,  2501, -3137, -3137,   885,  2641, -3137, 11834,
    2737, -3137, -3137, 12522, -3137,  2545,  1358,  2631,   146, -3137,
   -3137,  2613, -3137, -3137,  2664,  1101,  2512, -3137,  1092, -3137,
   -3137, -3137, -3137,    89,  1938, -3137,  2295, -3137, -3137,  2472,
    1514,  1350, -3137, -3137,  2473,  2021,  2023,  2026, -3137,  5140,
    2067,  1938, -3137, -3137,  2039, -3137,  2075, -3137, -3137, -3137,
   -3137, -3137,  1636,  1636,  1749,  1749,  1934,  1934,  1934,  1934,
     107,   107,  2070,  2176,  2168,  2171,  2527,    85, -3137, -3137,
   -3137, -3137, -3137, -3137,  2478,  2480, -3137,  2479,  1993,  5412,
    1725, -3137, -3137,  2532,  2534,  2544, -3137, -3137,  2546, -3137,
   -3137,  2643,  2648,  1591, -3137,  2529, -3137,  2642,  2539, -3137,
    2537,  2778,    78, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  2636,    35,    56, -3137,  2541, -3137,  2627,  2554,   712,
    2557,   249,  2622,   500,  2698,  2679,  1515,  2681,  2703,  2702,
    1523,   930,  2563,  2705,  2709, -3137, -3137, -3137, -3137, -3137,
    2607,  2564,  2565,  2615,  1591,  2809, -3137, -3137,  2649, -3137,
   -3137, -3137, -3137, -3137,  2716,  2574,  2685,   604, -3137, -3137,
    2581,   705,   731,   239,  1270,    24,   683,  2584,  2585,  2820,
    2590,  2822,  2591, -3137, -3137, -3137, -3137,   690,  2589,    93,
    2594, -3137,  2756,  2592,  2758,  2668,  2601,  2600,   523,  2606,
     115, -3137, -3137, -3137, -3137, -3137, -3137,  2605,  2687,  2776,
   12984,    56,  1600,  1591,  2611,  2844,  1080,  2612,  1591, 13138,
    2697,  1634,    50, -3137,    50, -3137,  2616,  2856,  2373,  2617,
   -3137, -3137,  1591,  2810,  2373,  1591, -3137,  2840,  2735, 11834,
     828, -3137, 11834,  2829, -3137,  2873, 13908, -3137, -3137,  2640,
   -3137,  2373,  1892, -3137,  1090, -3137, -3137,  9458,   871, -3137,
   -3137, -3137, -3137,  2608,  2634,  2608, -3137,  1713, -3137,  2107,
    1706,  1706, -3137, -3137,  8138,  9458,  2774,  2650,  1715, -3137,
    2645, -3137, -3137, -3137, -3137,  2655, -3137,  2283,  2657,  1672,
      42,   871,  2644,  2656,  2654,  1591,  2723, -3137, -3137, -3137,
   -3137,  1682, -3137, -3137,  2861, -3137, -3137, -3137, -3137,  2639,
   -3137,  1591,  2658,  2659, 13908,  2740,  1482,   871,  2660,  2661,
   -3137,  2662, -3137,  2843,  2847,  2292, -3137, -3137,  1420,  8402,
    1591,  2666, -3137, -3137,  1483,  2855, -3137, -3137, -3137, -3137,
   -3137,  2742, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
    2743, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137,  2746, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137,  1591,  2762, -3137,  2667, -3137,
   -3137, -3137,  1340,   863, -3137,   532,  2628,  2628, -3137,  2662,
    2599, -3137, -3137, -3137,  2812, -3137,  2867, -3137, 11834, 11834,
    2904,  1023, -3137, -3137, -3137,  1098,  1117, -3137, -3137, -3137,
   -3137, -3137, -3137,  1134, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,  7610, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137,  2677, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137,  2667,  1591,  2857,  1591,  2748,
    2846, -3137, -3137,   -11, -3137, -3137, -3137,  1591,   821,  2690,
   -3137, -3137,  1397,   821, -3137, -3137,  2692, -3137,  2791, -3137,
   -3137,  1719, -3137,  2693, -3137, -3137,  2918,   610,  1591,  2821,
    2919,  1634,  2672, -3137, -3137,  2678, -3137,  2663,   614,  1107,
      25,  1522,  2500,  2699, -3137, -3137,  2669,  2694, -3137,   147,
   11834, -3137, -3137, -3137,  2695, -3137, -3137,  1721, -3137,  1285,
   13908,   367,  1591,  1591,    67, -3137,  1591, -3137, -3137,  2839,
    2835, -3137,   903, -3137, -3137, -3137, -3137, -3137,  1938,  1785,
    1352,  1553, -3137,  3485,  3485,  3485, -3137, -3137,  1938, -3137,
    1938, -3137, -3137, -3137, -3137,  2670, -3137,  2671, -3137, -3137,
   -3137, -3137,  2696,  2711,  2797,  2936,  2712,  2789,  2802, -3137,
    2714,  2719, -3137,  2721, -3137, -3137,   901,  1372,  2722, -3137,
   -3137,  2808,    61,   207,  1568,  2730, -3137,    73, -3137,  1591,
    1591,  2767,  2718, -3137,  1155,  1600,  1591,  1591,   936, -3137,
    2877,  1591,  2833,  1591,  2905,  2750, 13908,  2894,  1591,  1591,
    1591, -3137, 13908,  1591,  1591,  1591, -3137,  1591,  1591, -3137,
    1591, -3137, -3137,  1591,  2282,  1591, -3137,  1591,   604, -3137,
    1591, -3137, -3137,  2290, -3137,   444, -3137,   390,  2732,   390,
    2732,  2798,  2736, -3137,  2738,  2734,  1640,   148,  2739,  2784,
   -3137, -3137,  1591,  2745, -3137,  2828,  2860, -3137,  2741,  2617,
   -3137,  2749, -3137,  2749, -3137, -3137, -3137,  1383,  2752, -3137,
   -3137, 11834, 11834,  2757,  1591, -3137, -3137, -3137, -3137,  2754,
    1591,  2759, -3137,    36,  2760,  2858,  1591,  2849,  2763,  2747,
   -3137,  1591,  1591,  1325,  1591,  1723, -3137, -3137, -3137, -3137,
    2925,  1591, -3137, -3137, -3137, -3137, -3137,  1729, -3137, -3137,
   -3137,  1009,  3006,  2697, -3137,  2887,  2889,    50, -3137,    50,
    2617,  1591,   878,  2765,  1186, -3137,  2885,  2769,  3019,  3022,
     737,  2868, 11834, -3137,  2735, -3137,  2980, -3137, -3137,  1591,
   -3137,  2790,  1591,  3025,   150,  2561,  2800, -3137, -3137, -3137,
   -3137, -3137, -3137,  2801,  1731,  1733,  2799, -3137,  2774,  2862,
    2796, -3137,  8666,  9458,  6611,  2723, -3137,  2412,  2412,  1541,
   -3137, -3137,  2804,  9458, -3137,  6398, -3137,  1655, -3137,  2963,
    2966, -3137,  1739,  2813, -3137, -3137,  2412,  2412,  1547,  2805,
    2806,   449, -3137,  1754, -3137,  2823, -3137,  2654,  1482, -3137,
   -3137, -3137,  2901,    14,    14,  2825, -3137, -3137,  2898, 12676,
    2908, -3137,    42,  2476, -3137, 11834,  3005,  3058, 11834, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  1775, 13908,  3002,    14, -3137, -3137,  1527,  3003,  2811,
    2950,  2640,   837, -3137,   821,  2545,  1397,  1591, 13292, -3137,
   13908,   694,  3028,  2817,  1016,  2888,  3007,  1591,  2848,  1591,
    2965,  2831, -3137, -3137,  1591,  2834, -3137, -3137,   715,  2662,
    9458, -3137, 11834, -3137, -3137,  2892,  2694, 12522, -3137,  1591,
    2984, -3137, 13908,  2859,   146, -3137,  1370,  1591,  1591,  3079,
     367, -3137, -3137, -3137, -3137, -3137,   443,  3014, -3137, -3137,
   -3137, -3137,  2972, 13908, -3137,  1154, -3137, -3137,  2041,  3485,
    2052,  1834,  1960,  1356, -3137, -3137,  3162, -3137, -3137, -3137,
   -3137, -3137, -3137,  2841,  2842, -3137,  2845,  3089, -3137,  2850,
   -3137, -3137, -3137,  2853, -3137,  2854, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,   464, -3137,
   -3137, -3137,  2890,  2874, -3137, 13138,  9458,  3029,  2953,  3030,
    2878, -3137,  2900,  2932,  1071, 13908, -3137, -3137,  2880, -3137,
    2689, 13908, -3137, -3137,  2875,    81,  2965,  2973,  2974,  2975,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,    27,  3020, -3137,  1591, -3137, -3137,  2883,
    2732, -3137, -3137,  2732,  2872, -3137, -3137, -3137, -3137, -3137,
    2964,  2732, -3137,  2893, -3137,  2895, -3137,  2886, -3137,  2876,
   -3137,   -50,  2896, -3137,  2897, -3137,   713,  2879, -3137, -3137,
   -3137, -3137, -3137, -3137,  2881, -3137, -3137,  2891, -3137,  2884,
    2899,  2882,  1591, -3137,  1591,  2902, -3137,   370, -3137,  2903,
    2906,  2373, -3137, -3137, -3137,  3059,  1325,  2907,  2909,  2937,
   13908,  2910,  2911,   878, 13138,  3136, 13908,    -9, -3137,  3052,
    3055,    50,  1070,  1119,  2697,   708, -3137, -3137,  2912,  2914,
    2617, -3137,  1530, -3137, -3137, 11834, -3137,  2913,  2917,    -9,
    1591,  2995,   402,  3090, -3137, -3137, -3137,  2920, 13908, -3137,
    2922,  9986, -3137, -3137,  2774,  2774,  2774,  3046, -3137,  3091,
    2774, 13908, -3137,  1796,  2921,  2283,  2923,  1531,  2545,  2608,
    2608,   871,  2915,  2924,  1591, -3137, -3137,  2926,  3142, -3137,
    1482,  1482, -3137, 13908, 10514,  2608,  2608,   871,  2929,  2931,
   -3137, -3137, -3137,  1152, -3137, -3137,    14,   994, -3137, 13908,
    3017, -3137,  1797,  2928,  3033,  3116, -3137, 11834, 11834, -3137,
   -3137, -3137,  2946,    14,    38, -3137, -3137,  2083,  2083,   871,
    2949,  1200,  2723, -3137, -3137, -3137, -3137, -3137,  2545,  2956,
   13908, -3137,   765, -3137,  2945,  2951, -3137,  2959,  3009, -3137,
    2938, -3137,   885,   610,  3054, -3137,  2967,  2697, -3137, -3137,
    2958, -3137, -3137,  1780,  1799,   147, -3137,  1168, -3137, -3137,
   -3137, -3137,   201,   743,   367,  2947, 13908,  2399, -3137, 14422,
   -3137,  2960, -3137, 13908,   841,  1710,  3143,  2976, -3137, -3137,
    2839,  2916, -3137,  3485,  3485,  2060,  3485,  2076,  1991,  3485,
   -3137, -3137, -3137,  3118, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  1591,  2697, -3137,  1591, -3137,  2982,  2978,  2987,  2981,
      62,  2878, 13908,  3074,  1591,  2985,  3060,  3219, 13908,  1203,
   13908, -3137,   147,  1800,  1591,  2992,  2994, -3137, 13908,  1591,
    1591, -3137, -3137, -3137,  2993,  2983, -3137, -3137,  2979,  2986,
    1591,  1591, -3137, -3137, -3137,   622, -3137, -3137,  2749,  2749,
   -3137, -3137,  1591, -3137,   417,   504, -3137,  3049, -3137, -3137,
    1591,  3104,  2988, -3137,  3105, -3137,  3234,  3113,  3008,  3059,
    3088, -3137, -3137,  2991, -3137, -3137, -3137, -3137, 13908,  2697,
   -3137,  3011,  1806, -3137, -3137, -3137, -3137, -3137,  1119, -3137,
   -3137, -3137, -3137, -3137,  2989, -3137,   635,  2990,  2293, -3137,
    2996,  2997, -3137, -3137, -3137,  3200, -3137,   -48,  3096,  2464,
   -3137,  1591, -3137,  3097, -3137, -3137, -3137,   821,  3175, -3137,
   -3137, -3137,  3240,  3156,  3032, -3137, -3137, -3137,  3021, -3137,
    8930, 13908, -3137, -3137, -3137, -3137,  2412,  2412, -3137,  3253,
   -3137, -3137, -3137, -3137, -3137,  1807, -3137, -3137, -3137, -3137,
   -3137,  2412,  2412,   449,   994,  3201, -3137, -3137,  1823,  3035,
      -9, 10514,  3034, -3137,  1200,  1591, -3137, -3137, 13908,    38,
    3012,  2412,  2412, -3137,  1540,  3038,  3039,  3041,    -9,  3036,
    1508, -3137, -3137,   778,   640, -3137, -3137, -3137,  1842, -3137,
    3040, 13292,  2545, 10778, 13908, -3137,  3135, -3137, -3137,  3129,
    3098,  3144, 13908, -3137,  1591,  3197,  9458, -3137, -3137, -3137,
    9458,  3042, -3137, -3137, -3137,  1591,  1843,  3053,  1497,  3208,
    3155, 14422, 11042,  1591,  1851,  3043,   367,  1591,  1591,  1591,
    1591,  9458, 14422,  3045,  1591,  9194,  1851,  2139,  9458,  1469,
    3048,  3047,  3050,  3051,  3057,  3061,  3062,  3063,  3064,  3065,
    3066,  2321, -3137, -3137,  3056, -3137, 14284, -3137, -3137, -3137,
    3067, -3137, -3137, -3137, -3137, -3137,  1591, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,  1598,
   -3137,   201,  3193,  3069, -3137, -3137,  3075, -3137,  1366,  3252,
     146, -3137, -3137, -3137, -3137,  3485, -3137,  3485,  3485,  2085,
   -3137, -3137, -3137,  2965,  1856, -3137,  3190,  2697, -3137, 13908,
    3074,  3074,  3074,  1857,  3068,  3145,  2932,  1591,  3070, -3137,
    3071,  1858,  3282,  3220,  3083,  3285,  1859, -3137,  2689, 13908,
    3244, 11834, 11834, -3137, -3137, -3137,  1591, -3137, -3137,  3081,
    3087, -3137,  3215, -3137, -3137,  2897, -3137,  3073,  3076, -3137,
    3312, -3137,  1591,    -9,  3078,  2937,  3294,  3077,  1860,  1887,
    3328,   676,  3167, -3137,   495,  3330,  1888,  3084,   510, -3137,
   -3137, -3137, 11834,  3080,  3086,  2979, -3137,   -48, -3137,  1276,
   -3137, -3137,  3216,  3106,  1487,  3003,  3003, 11834,  3331,  3094,
    3238, 13908, -3137,  1905,  2283,  2608,  2608, -3137, -3137, 10514,
    2608,  2608, -3137, -3137,  3072, -3137, 13908, 10514, -3137,  1907,
    2928,  1468,  3111, -3137,  3012, -3137, -3137,  2608,  2608,  2083,
    2083,   871,   561,  1591,    -9,  3112,  1200,  3242, -3137,  3242,
    3242,  3267,  1591,  1591,  1591,  2213,  3343,  3196,  9458,  3291,
     461,  3103,  3115, 13908,  1591, -3137, -3137, -3137, -3137, -3137,
    1591,  3085, -3137,   885,  1591,  1909, -3137,  3131,  3108, -3137,
     147, -3137,  9458, -3137, -3137,  1442,   842, 13908,    -9,  3230,
   14284,  9458, -3137,  3209,  3321,  3210,  1467, -3137, -3137,  3359,
    3212,    21,  2341, -3137,  3127, -3137,  3231, 14377, -3137,  3130,
    1578, -3137,  3132,  3235,  3133,  1232,  3292, -3137,  3140,  3147,
    1591, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  3141,  3149,  3232,  3325, -3137, -3137, -3137,  3153, 13908,
    3157,  1591, 13908,  1710, -3137, -3137,  3384,  1622,   367, -3137,
   -3137, -3137, -3137,  3485, -3137, -3137, -3137,  1591,  1591,  3171,
    1915,  3145,  3145,  3145, -3137,  3154,  3225, -3137,  3060,  1916,
   -3137,  3198, 13908,   676,  3243,  3173,  3177, -3137, 11834,  2689,
   -3137,   147,  3305,  1922, -3137, -3137,  1924,  1242,  3160, -3137,
    1591, -3137,  3320,  1591, -3137,  2464, -3137, -3137, 11834,   217,
   -3137, -3137,  1451,  3191,    -9,  1591, -3137,  1208, -3137,  3418,
     572, -3137,   821, -3137, -3137,  3168, -3137,   504, -3137, -3137,
    1716, -3137, -3137,  3081, -3137, -3137,   390,  2732, -3137, -3137,
    3187, -3137,  2723,  2723, -3137,  3188, -3137, 11834,  1040,  3194,
    3419, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  1926, -3137, -3137,  9458, 11306,  2723, -3137, -3137, -3137,
    2412,  2412, -3137,  3199,  3195,  3202, -3137,  1617,  3192,  3203,
    2213,  1508, -3137, -3137, -3137, -3137,  1200,    42,  1930, -3137,
     555,  2628,  3205,  3178,    42, -3137, -3137,  9458,  9458, -3137,
    3429,  3373,  3103,  3354,  3308, 11834, -3137, -3137, -3137,  3204,
    3129,  3206,  3211,  3341,  3374,  3074, -3137, -3137,  3207,  3221,
    3217, -3137, -3137,  3222,  3224,  2321,  3229,  3401,  3231, 11834,
    3321,  3209, 14422,  3405, -3137,  1591, -3137, 14422,  9458,  3213,
    1591,  1591,  3251, -3137, 11834, -3137, 14422,   688,  3372, -3137,
    1591, -3137,  9458, 13908,  1591, -3137,  1591,  3248, -3137,  9458,
    1175, -3137,  3232, -3137, -3137, -3137, -3137, -3137,  1518, -3137,
   -3137,  3283,  1643,  1591,  1932, -3137, -3137, -3137,  1591,  3304,
   -3137, -3137, -3137, -3137,  3254,  3360, -3137,  3353, -3137, -3137,
   -3137,  2302,  1373, -3137, -3137,  1591,  1591,  3268,  1933, -3137,
    1315,  3474, -3137, -3137,  3255, -3137, -3137,  2767,  3421, 11834,
    3422,  1591,  1591, -3137, -3137,  3245, -3137, -3137, -3137,  1318,
   -3137,   497, -3137,  3247,  3256,  3266,  3396, -3137, -3137, -3137,
   -3137,  3271,   579, -3137, -3137,  1918, -3137, -3137,  3486, -3137,
    3270, -3137,  1591,   640,   640, 11834,  2694, -3137,  1131, -3137,
     913, -3137,  2251, -3137, 11834, -3137,  3347, -3137,  1939, -3137,
   -3137,  2545,  2608,  2608,  9458,    42,  6611,  3257,    42,    42,
    1526, -3137,    42,  1591,  1591, -3137,  2213,  3250,  3315,  3279,
   -3137, -3137, -3137,  5456,  9458, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,  2821,  3375,  1591,  1942, -3137,  3258,  1373,
    3280,  3284, -3137,  3376,  3273,  1140,  1591, -3137, -3137,  3231,
    3471, -3137, 14422,  3508,  3297, 14284, -3137, -3137,  1943,  3467,
   11834,  3313,  3292,   882, 14422, 14422,  9458,  9458,  3496, -3137,
   -3137,  3301,  3302,  1486,  3303, -3137,  3306,  3307,  3231,  3231,
    3446, -3137, 13908,  3538,  3310,  1591, -3137,  3311, 13908, -3137,
   -3137,  3317, -3137,  1591,  1591,  1950, -3137,  1591, -3137, -3137,
   -3137,  3300, -3137,  1591, -3137,  1373, -3137, -3137, -3137,  1591,
   -3137, 13908,  3171,  3324, -3137, -3137,  3326, -3137,  3327,  3416,
    3322, -3137,  9458,  3413,  3466, -3137,  3487,   147, -3137, -3137,
    3333,  3334, -3137,  1591,  1956, -3137,   676,  3020, -3137,  1947,
   -3137, -3137, -3137, -3137,   390, -3137,  3291,  3291, -3137,  3563,
   -3137,  3314, -3137, -3137,  1551,  1966, -3137,   -10,  3347, -3137,
   -3137, 11306, -3137, -3137, -3137,  1973, -3137, -3137,  1659,  3338,
   -3137, -3137,  9458, -3137, -3137,  2628,    42,  3332,    30, -3137,
   -3137, 13446,  3340,  3344,  3345, -3137, -3137,  3335, -3137, -3137,
   -3137, -3137,  1591,  1976, -3137,  3476, -3137,  3341, -3137, -3137,
   -3137, -3137, -3137, -3137,  3336, -3137,  3567,  3342, -3137,  3531,
   -3137,  1591,  3352, 11834,  1591,  7082, 14422,  3231,  3231,  3516,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137,  1591, -3137,  1591,
   -3137,  3346, -3137, -3137,  9458, -3137,  2697, -3137,  3360,  2476,
   -3137, -3137, -3137, -3137, -3137, -3137,   676,  3305,  3305,  1591,
    1591,  3356,   147, -3137,   147,  3074, -3137, -3137,  1019, -3137,
    3396,  1342, -3137, -3137, -3137,  3373,  3373,  1253, -3137, -3137,
   -3137, -3137, 11834,  3337,  3339,  3447, -3137, -3137, -3137,  6611,
      42, -3137, -3137, -3137, 11570, 13600,  3250,  3520, 13908, -3137,
    3532, -3137, 11834, 11834,  5732,  5456,  3451, -3137,  3375,  1591,
   -3137, -3137,  3351, -3137,  1591,  1978, 11834,  3388,  3355,  1303,
    1984,   688,   688,  3357, -3137, -3137,  1591,  3364,  2697, -3137,
    3500,  1348,  2767,  2767,  3361, -3137, -3137,  3074,  3074,  3145,
      33, -3137, -3137, -3137, -3137, -3137, -3137,   934, -3137,  2255,
   -3137, -3137, -3137,  1106, -3137,  3371, -3137,  3379,  3380, 13908,
   -3137, -3137,  3377,  3381,  1987, -3137, 13446,  2012, -3137, -3137,
    2013,  7346, -3137,  2031, -3137, -3137, -3137, -3137,  3498, -3137,
    3397, -3137,  3365, -3137,  3388, 11834,  3292, -3137,   792, -3137,
   -3137, -3137, -3137, -3137,  1167, -3137,  3171,  3369,  3378,  1591,
    3145,  3145, -3137,  2890,  3478, 11834, -3137, -3137, -3137,  2825,
    3484, -3137,    42,    42,  3385,  1230, -3137, -3137, 13908,  3549,
   -3137, 11834, -3137, -3137, -3137,  5732,  1591,  1591, -3137, -3137,
    3292, -3137,  1591,    96,   565,   565, -3137,  3305,  3305,  3515,
   -3137, -3137, -3137,  3390,  2032,  3470, 13292, -3137, -3137, -3137,
     776,   776,  2034, -3137,    42, -3137, -3137,  3392,  3393, -3137,
   -3137, -3137,  3472, -3137,  1591,  3386, -3137, -3137,  3382, -3137,
   -3137, -3137,  2767,  2767,  1591, 11834,  2890,  3395,    10, -3137,
   -3137, -3137,  1230, -3137, 13754, -3137,   515,  3389, -3137, -3137,
    3398,  3400, -3137,  2035, -3137, 10514, -3137, -3137, 13908, -3137,
    2038, -3137,  3624, -3137, -3137,  3495, 11834, -3137, -3137, -3137,
    2890,  2042,  2048, -3137, -3137, 13754,  1678,  3403,  2063, -3137,
   -3137, -3137, 13908, -3137,  1230, -3137, -3137, -3137,  3408,  2170,
    2062, -3137, 11834, -3137, -3137,  2066, -3137,  1230,  1230,  1230,
    1230,  1230,  2079, -3137,  1230,  2170,  2062,  2062, -3137, -3137,
   -3137, -3137
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
   -3137, -3137,  3689, -3137, -3137, -3137, -3137,   589, -3137,  -298,
    1740,  1742,  1694,  1738,  2944,  2948,  2952,  2943,  2954,  2942,
     -96,  -286, -3137,  -347,  -272,   104,  1587, -3137, -3137,  3415,
   -3137,   100,  -224, -3137, -3137, -3137, -3137,  3635,  1631, -3137,
   -3137, -3137,  2619, -3137,  3619,  3348,     3,     1, -3137, -3137,
      -7,    28, -3137, -3137,   -86, -3137,  2934,  -239,  -684,  -683,
    -677, -3137,  -340, -3137,  1440,  3362, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137,  3643,  1130,  3402,  1233, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137,   -77, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137,  3082, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,  3150, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  2673, -3137, -3137, -3137, -3137,  2744, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,  1685,  1855, -3137, -3137,   112, -3137, -3137,  2014, -1838,
   -3137, -3137, -3137, -3137,  3664,   469,  3668,  -164,  1083, -3137,
   -3137,  3114,  -156, -3137, -3137, -3137, -3137,  1343, -3137,  2927,
   -3137, -3137,  2961,  2962,  -737, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137,  3604,  2761, -1021,  1879,  1283, -3137, -3137, -3137,
   -2122,  1024, -3137, -3137, -3137, -3137, -3137,  1058,  1064,  2047,
   -3137, -3137, -1674, -2032, -3137, -3137, -3137, -1712, -3137, -3137,
    2078, -3137,  1400, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137,   620, -3137, -3137, -3137,   354, -3137, -3137,
   -3137,  2955,  -104, -3137, -3137, -3137,   937, -3137,   545,  1171,
   -3137,   723, -3005, -3137,   952, -2823, -1113, -3137,   703, -1998,
   -3137, -3137,  2572, -3137, -3137, -3137, -3137,  2519, -3137, -3137,
   -3137, -2578, -3137, -3137, -3137,   467, -3137, -2762,   626, -3137,
     563, -3137, -1658,  2258, -3137, -3137,   406, -2617,   721, -1214,
   -1257, -2050,   435, -1790, -2797, -2840, -3137,  1688, -1172, -2681,
   -3137,  1816, -1248,  1714,  1453, -3137, -3137,   732, -3137, -3137,
   -1809, -3137, -3137, -1484,   189, -3137,  -355, -1800,   735, -3137,
   -1053, -2058,  1170, -3137, -3137, -3137,  -804, -1246, -3137,  1927,
   -2341, -3137, -3137, -3137, -3137,  3713,  2049, -3137, -3137, -3137,
   -3137, -3137, -3137,  -842,  1109,  1120, -3137,  2388, -2461,  1133,
   -3137,  1123,  1207,  1247, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137,   264,  1345, -2145, -3137,  1091,  1302, -3137,   547, -3137,
   -3137, -3137,   308,  1322, -3137, -3137,   549, -1019, -2350, -3137,
   -1271, -1402, -3137, -3137,  2328,  2051,  1952,  -853,  3692,  1940,
   -3137,    31, -3137, -3137,  2818,  3172, -3137,  -126, -3137,  -773,
    2061, -1023, -3137, -3137,  2968, -1063,  -179, -3137, -2406, -3137,
   -2382, -3137, -3137,   440, -3137, -3137, -3137,   255, -3137, -3137,
     372, -3137, -2858, -3137, -3137,   224, -3137, -3137, -2777, -3137,
   -3137, -3063, -3137, -3137,   203, -1145, -2748, -2077, -3137, -3137,
     718, -3137, -3137,  -214, -2677,   441,   325, -3137, -3137,   322,
     326, -3137,   447,  -878,  -588,   902, -3137,  1138,   907,  -692,
   -1106,  1955, -2478, -1098, -1562,  1961, -2225, -3137, -3137,  1646,
     910, -1813,  -115, -3137,  2933,  2930,  3295, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137,    75,  1057,  -149, -3137,  3004,
    1644,  1645,  1089, -3137, -1361, -3137, -3137,  2597,  2115,  2602,
   -3137,  3092,  -966, -3137, -3137,   485, -1617, -3137, -3137,   788,
   -3137, -3137,   777, -3137,   507,  -913,  -296, -3137,  2112, -3137,
   -3137, -3137, -3137, -3137, -3137, -1090,  -707, -3137,  1977, -3137,
   -1953,  1324, -2930, -2497, -1814, -3137,  -587, -2853, -2214, -2513,
   -3137, -1786,  1087, -3137, -2212, -3137,  1384, -3137,  1969, -3137,
   -3137, -3137, -3137, -3137, -1015, -3137, -3137, -3137,   693, -2694,
   -3137, -3137, -3137,   881, -3137, -2939, -2471, -2512, -3137, -3137,
   -3137, -3137, -3137, -3137,  -908, -3137, -2586, -3137,  1143, -3137,
     915, -3137, -3137,   919, -3137, -2769, -3137, -3137, -3137,   416,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137,  2674, -1217, -3137,
   -3137, -3137, -3137,  2682, -3137,  1821,  1844, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
    -344,  1792, -2054,  1873,   843, -3137,  1817, -3137,  1828, -3137,
   -3137, -2076, -3137, -3137, -1668,  1603, -3137, -3137, -3137, -3137,
   -3137, -3137, -3137, -3137,  1673, -3137, -3137,  1129, -3137, -3137,
   -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137, -3137,
   -3137, -2055, -3137, -3137, -3137, -3137, -3137, -3137,  1284, -3137,
    1054, -3137,   847, -3137, -3137,   101,  -932,  -570,  2957,  1538,
    2567, -3137, -2155, -3137, -3137,  -896, -3137,  -887, -1312, -3137,
   -3137, -2825, -3137, -1209, -3136, -3137,   590, -1475, -3137
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule which
   number is the opposite.  If zero, do what YYDEFACT says.
   If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1928
static const yytype_int16 yytable[] =
{
     560,  1900,   578,   654,  1426,  1568,   755,  1367,  1595,  1605,
     751,  1902,  1903,  2158,  1378,   765,  2206,  2092,   665,   966,
    2187,  1365,  1118,  1359,  1360,  2308,  1851,  2206,  1611,  2373,
     410,  1701,  1115,  1545,   638,   639,   640,  1550,  1966,  2204,
    2749,   414,  2208,   656,   401,   103,   661,  1559,   735,   980,
     646,  1839,  1353,  1841,   101,  2906,  2093,  1127,  2376,  1683,
     110,  2376,  2361,  2101,  2834,  1808,   128,  3064,  1308,  2376,
    2547,  1800,  2881,  2882,  2883,   748,   786,  2396,  1422,  3117,
     104,  2836,  1812,  1835,  2856,  2116,  1489,  3140,  1819,  1390,
    2810,  2414,  2555,  2442,  2497,  2593,  3110,   330,  2751,  2242,
      59,  2827,  2511,  2512,   712,  1833,  1615,  2723,  2720,  3218,
    1809,  2439,  3285,  2851,  2434,  1816,  3037,  1262,   745,  3098,
    3099,  3100,   345,   767,  3231,  2651,    22,    22,    22,   804,
    1185,  3250,  2510,    22,  1188,  1738,   657,  2667,    22,   728,
     729,   730,   340,   340,    22,   804,  3415,   860,   823,   428,
    1667,   935,  2371,    59,  2164,  2218,  1932,   731,    59,    59,
     603,  1936,  1109,    59,  2029,    22,  1302,   118,   794,   795,
    3563,   910,  1963,  1485,   774,   775,   776,   777,   778,   779,
     780,   781,   782,   783,  1271,   140,  2302,   692,   429,  3443,
    1217,  1358,  2365,  2317,  3455,  1502,   982,  3228,  1503,  1113,
    3050,    22,  1964,  1661,   329,   911,   833,  1211,   220,  1929,
      59,  2951,   673,  3626,   118,  1056,   708,  1758,  3564,  1990,
    2714,    59,    59,   836,  1352,   389,   402,  1314,  1264,  1272,
    1194,  2198,  1477,  2039,  1014,  1759,  1662,  2543,  3129,  1368,
     651,  2129,  1468,  1265,  1760,  1761,  1228,  1273,  1836,  1330,
    1331,   410,   579,  1058,  1220,  1119,  1557,  1963,  2383,  2384,
     637,  2715,   768,   769,   770,  1429,   418,   637,    85,   655,
    3140,   659,  1305,  1430,   664,   666,   861,   847,   848,   849,
      86,   852,   853,   419,   855,   856,  2971,  1964,  1492,  1739,
    1218,  1934,  2643,  2130,  1059,  1221,  1266,  1229,  2856,  1219,
    3382,  1230,  1493,  1469,   874,   875,   876,   877,  1663,  2683,
    1015,  2385,   841,  2716,  3038,  2856,  1612,   401,  1195,   724,
    1274,  2040,  3627,  1275,   410,   983,  1120,  1855,  1558,  1504,
    1057,   707,  1762,  1212,  1510,   894,   345,  1511,  2550,  2366,
   -1927,  2689,  1731,   744,  2031,  1679,   984,  2593,  1022,  1023,
    1930,  3444,    90,  2531, -1927,    91,  2422,  2737,  2593,  2761,
    2991,   666,   912,  2593,  1318,   340,  3051,  2032,  1267,  2700,
    3565,   340,  1678,  3456,   551,   552,   912,  1679,   141,  1668,
     430,  1894,  2593,  2709,   182,  1740,  1307,  2754,  2372,   828,
     766,  1669,   431,    92,   551,   658,   666,   666,   666,  2352,
     936,   862,   551,   552,   985,  1141,   817,   604,  1110,   765,
    1137,  1145,  1146,  1147,   666,   765,   816,  1222,   732,  2245,
    3596,   551,   552,  1475,   605,  1156,   943,   944,   829,   946,
     947,   948,   949,   950,   951,   709,   953,   834,   955,  1664,
     329, -1066,  1505,  1506,   835,  1276,   963,  3209,   735,  2524,
    3129,   986,  3217,  3477,  1763,  2033,  1665,  3628,  3484,  2532,
    1680,  1844,  1845,  3384,  1897,  1185,  1901,  1188,  1512,  1130,
    1179,  1838,  1533,  1533,  1533,  1533,  1533,  1533,  1533,  1533,
    1533,  1533,  1533,  1533,   805,  1155,    51,  3557,  3558,  1159,
    1160,  1161,   404,    52,    59,  2419,    51,  1932,   389,  1158,
    1977,  1640,    51,    52,  1856,   741,  2089,    81,   113,  3431,
    2593,  1074,  1075,   329,  1077,  1129,  1883,  1144,   796,   797,
    1178,  1716,  1135,   814,  1546,   815,  1096,  2621,  3475,  1098,
    1875,  3379,  1732,   846,   666,   666,   666,  2951,   666,   666,
     854,   666,   666,  1187,   858,   859,  3544,  2125,  2551,   784,
    1197,  3226,  1808,  1425,   870, -1000,  2086,  3214,  2661,    51,
   -1000,   666,   666,   666,   666,   226,    52, -1049,  2034,   880,
     881,  3222,  2051,   883,  3127,  3026,  3225,  2459,  2460,  2461,
     107,  1513,  3144,  2465,  1001,  3234,  -892,  1381,  2776,  -415,
    3180,  3140,  1577,  2161,  3492,  3493,  2593,  2879,  2311,  1991,
    3525,  2970,  2803,  3501,  2980,  2981,  2400,   771,  3179,   772,
    1921,   773,  1416,  2593,  2820,  3591,  1612,   651,  2699,  3491,
     830,  3696,  2687,  1678,  2102,  1679,    93,  3650,  3651,  2452,
    2934,  2936,   831,  3375,    94,    95,   902,  2414,  1434,  3315,
    1895,  3711,   551,   552,   354,   410,  1201,    79,  2083,  2931,
    1775,  3140,  3664,  2858,  2938,  2206,  3091,   358,    22,  1959,
     359,  1934,  3395,  3396,  1382,  1934,  2337,   884,  2338,  1898,
    2900,   360,   361,  1138,   226,   850,  3116,   226,  1289,   938,
    1425,   941,   942,   666,   666,   525,   666,   666,   666,   666,
     666,   666,   952,   666,   954,   666,  1002,   957,   958,  2083,
    3665,  1270,  1202,   666,   850,    80,  2435,   971,  2436,  1294,
    2856,  1686,  2435,  2856,  2436,   409,  1435,  1309,   651,   410,
    3616,  2685,  2856,  1290,   533,  2312,  1328,   551,   552,  1383,
    1334,  2401,   535,  1180,  1003,  2087,  2801,  3562,  3602,  3387,
    3388,  2288,  2795,   551,   552,   966,  1531,  1531,  1531,  1531,
    1531,  1531,  1531,  1531,  1531,  1531,  1531,  1531,  2778,  1150,
    2688,  2832,   666,  1578,  3386,  1352,  1566,  2776,   666,   666,
    1076,   666,  1078,  1079,  3632,  3633,  2083,  3592,  1338,  2453,
    1776,  1198,  1345,  2083,   766,   578,  1308,  3532,  1199,  1403,
     851,  3627,  1004,  1630,   551,   552,  1626,  1557,  3600,  3601,
    1408,  3481,  3482,  1291,  3346,  2084,  1721,   817,  1722,   551,
     552,  3654,   525,  1379,  1687,  1954,  1054,   101,   128,  1589,
    2339,  3624,  1417,  1384,  2435,  1203,  2436,  3614,  2593,  2267,
    2232,  1386,  1418,  2593,  1419, -1001,  2593,  3235,  3236,  2244,
   -1001,  1943,  2593,  1884,  2469,  3679,  1874,  3499,  2340,  2880,
     718,   533,  3666,  1636,  1055,  1476,  2930,  2367,  1302,   535,
    1486,  1487,  1625,  2983,  1775,  2438,   329,  1011,  2951,  1899,
    1935,  2937,  2237,  2345,  2856,  3143,  1277,  1278,  1209,  2777,
    1496,  3673,  1500,  3147,  2304,  1303,  1279,  1514,  1515,  1516,
    1517,  1518,  1519,  1062,  3614,  2406,  1062,  2473,  2474,  1547,
    3184,  3115,  2416,  2254,  1808,  3694,  1800,  1955,  3532,  1012,
    2435,   578,  2436,  2488,  2489,  2376,   600,  1280,  1647,  3560,
    3561,   551,  2984,   720,  1281,  1742,  3628,   169,   354,  1754,
    1342,   864,  1063,  3142,  1304,  1063,   409,  2778,  2593,  2203,
    3307,   358,    22,   757,   359,  1997,  1593,  1727,  3604,   763,
     764,  1743,  3708,  3709,  1723,   360,   361,   721,   666,  2389,
    1599,  2209,  2210,   409,  1305,  1293,   666,  1306,   651,  1297,
    1298,  1944,   651,  1729,   666,  1956,  1520,  1342,  2441,  1326,
    2225,  2226,  1353,   666, -1556,   354,  1333,   666,  3027,  1566,
    2925,  3237,  2553,  1013,  2180,   651,  2706,   169,   358,    22,
    1210,   359,   651,   651,  1348,  1351,  1013,  1122,  2593,   409,
    1080,  2593,   360,   361,   607,   718,   362,  2707,  3653,  1123,
    2593,  2593,   363,   364,   365,   366,   367,   368,  1863,   173,
    1389,   181,   666,   601,  2554,   579,  1348,  2926,   410,   734,
    1401,  1402,  1482,   893,  1744,  2947,   666,  1554,  2775,  3678,
     865,  1755,  1314,  1702,  1352,  1314,  2388,   666,  1703,  1627,
    1217,  1282,  1674,   608,  2437,  2293,  1728,  1745,  1218,  2438,
    2199,  1428,  3425,  1675, -1554,  3702,  1675,  1219,  1307,  1507,
    1283,  1284,  1508,  2622,  1497,   888,  1315,  3308,   720,  1315,
    1339,  3031,  1730,   354,   410,  1316,  1352,  1498,  1316,   651,
     651,   181,  2472,  1645,  1521,  1522,   358,    22,  2531,   359,
    2772,  3244,   666,  1480,   637,  2773,   666,   666,   666,  1670,
     360,   361,   721,  2774,  1220,   686,  1909,    87,  1557,  1910,
      67,  1524,  1525,  3032,  1526,  1527,   744,    82,  2423,  3153,
    3154,  1704,  1150,  1532,  1532,  1532,  1532,  1532,  1532,  1532,
    1532,  1532,  1532,  1532,  1532,  1480,   666,  1789,  1558,   150,
    2449,   579,  2525,  3171,  1555,  1221,  1556,  2593,  2458,   938,
     664,  1348,  2593,  1574,  1575,  2265,  1705,   966,  1103,   228,
     869,    67,  1317,    67,  2539,  1317,  3320,    67,  1499,  1318,
    1824,   116,  1318,  1827,  3671,    67,  1455,  3497,   160,  3498,
    1558,  1912,  2623,   666,  1913,   275,  2054,  1670,  3566,   889,
     609,   131,  1319,  1509,  1348,  2494,   276,  1609, -1412,  3385,
    1915,   928,   610,  1916,   418,   890,  1834,   929, -1927,   611,
     612,  1587,  2509,    68,  3151,   613,   891,  1918,    88,  1617,
    1919,   824,  1837,   614,  2268,  2023,  1104,  2280,  3242,    67,
     912,   399,  3432,  1250,   407,  3247,  1250,  2024,  1251,  2495,
    1911,  1251,   131,  3374,   551,   552,  1588,  1252,   718,  3321,
    1252,  2281,  1456,  2055,  3256,  2046,   172,  3500,  1618,  1113,
    2155,  1998,  2000,  3569,  2003,   354,    68,  1222,   228,  1457,
    3321,   228,  2318,  2004,  2005,  2006,  1458,  1459,   358,    22,
     362,   359,  1460,   277,  1654,  3593,   363,   364,   365,   366,
     367,   368,   360,   361,   275,  3157,  1461,   275,  2235,  3158,
    2047,  1062,  1996,   734,  2475,   276,   446,   704,   276,    22,
     409,  2319,  1462,  2341,  1443,  1914,   735,  1894,   705,  1463,
    2490,   720,  2357,   278,  3594,  2048,  2156,  1792,  2662,  1906,
    1907,  1464,  2007,   447,  1917,  1714,  1619,   362,  1153,  1253,
    1063,  3570,  1253,   363,   364,   365,   366,   367,   368,  2049,
      89,  1920,  2513,  2963,  2169,   721,   409,   409,   409,   409,
     409,   409,   409,   409,   409,   409,   409,   409,   409,   409,
     409,   409,   409,   409,   409,  3156,  3159,  1254,   282,  1255,
    1254,  3160,  2663,  2664,   409,  2112,  3157,  2050,  2358,  2320,
    1444,  1348,   277,  2170,   666,   277,  1465,  1228,   283,  1796,
    1348,   940,  3595,  2964,  2965,   706,  2786,  1445,  2967,  2968,
    1520,  3478,   651,   971,  2875,  1446,  1820,   132,  3292,  2665,
    1447,  1793,  2515,  1027,   713,  2978,  2979,  1831,  1028,   651,
     651,  1599,   278,  3121,  1448,   278,  1029,   135,   133,  1970,
    1992,   136,  3248,    67,  1794,   362,  2162,  1030,  1958,   714,
      67,   363,   364,   365,   366,   367,   368,  1449,  2168,   836,
     399,  2748,   753,   837,  1436,   838,   754,  3159,  3122,  1450,
    2169,   938,  3160,  1971,  1622, -1555,  1862,  2493,  3615,  2765,
   -1552,  1437,   839,   120,   651,   551,   552,   282,  3293,  1438,
     282,  1623,  1868,  1846,  1439,  1348,   137,  3294,  3295,  2516,
    2517,  3542,  2925,   840,   399,  3185,  3186,   283,  3506,  2170,
     283,  1885,  3296,  3639,  3640,   551,   552,  2518,  1734,   354,
    2868,  3267,  2548,    67,  2008,   134,  3139,  1031,   131,  2549,
     120,  1440,   358,    22,  1451,   359,  1735,  2733,  1521,  1522,
     551,   552,   403,  1441,  2080,  3615,   360,   361,   841,  2926,
    3297,   928,  3610,  1551,  3611,   718,  1892,  3063,   354,  1736,
    2735,  2736,  1552,   666,  2143,  1524,  1525,    57,  1526,  1527,
    3485,   358,    22,   842,   359,  2740,  2741,  2864,   651,  3615,
    2559,   898,  3434,  1032,   719,   360,   361,  3615,  2865,  3159,
     138,  2206,  2122,  2123,  3507,  2757,  2758,  1033,  1034,  1035,
    3615,  3615,  3615,  3615,  3615,  2141,  2142,  3615,  1442,  2925,
    2144,  1737,   908,   909,  2089,  2767,   139,  2945,  1678,  3625,
      57,  3271,  3272,  1691,  2768,   111,   112,  1923,   720,  1925,
    2481,  2482,  2769,  3282,  2325,  2327,  2925,   362,  1351,  2322,
     843,  3439,  2925,   363,   364,   365,   366,   367,   368,  1246,
     328,  3647,  2974,  2184,  2915,  2767,  2926,  1066,  1140,  1946,
    3503,   325,   721,   331,  2768,  1247,  3556,  3273,   806,   844,
   -1274,  3440,  2769,  2767,  1248,  3020,  1606,  2770,  2158,   332,
     551,   552,  2768,  2926,   807,  1692,  -517,  2305,   354,  2926,
    2769,  1976,  1986,  1987,  1989,  2306,  2025,   666,   551,   552,
     432,   358,    22,   409,   359,   326,  1693,  2117,  2026,  1694,
    3342,   551,   552,  1131,  1700,   360,   361,  2770,  1379,  2118,
     409,  2119,  1218,  1316,  2120,  2989,   806,   680,  2215,  1132,
     354,  1219,   806,   433,   806,  2770,  2246,   927,   806,  2249,
    2217,   681,  1143,   358,    22,  1881,   359,  1695,  1631,   973,
    2001,   974,  2218,  2030,  2328,   344,  1805,   360,   361,   409,
    2041,  2042,  2099,   975,  3028,  1806,  3029,  2052,  2053,  3035,
     408,  2100,  2057,  3133,  2059,  3134,  2986,  1348,  3030,  2064,
    2065,  2066,   434,  1348,  2068,  2069,  2070,  3135,  2071,  2072,
     354,  2073,  3045,  1599,  2074,  3046,  2078,  2837,  2079,   435,
     436,   666,  2168,   358,    22,  1853,   359,   437,  1471,   551,
     552,  3252,   438,  -517,  2169,   420,  1472,   360,   361,   548,
    1391,   439,  2807,  2107,  1391,  2295,   440,   551,   552,   553,
    1392,   554,  1393,  3089,  1392,  1429,  1393,  1853,  1759,   354,
    3333,  3334,  3090,  3252,   327,   971, -1554,  1760,  -571,   441,
    3452,  2127,   358,    22,  2982,   359,  2471,  2133,  1520,  1417,
     399,   442,   666,   666,  2255,  2148,   360,   361,  2256,  1418,
     695,  1419,  2152,   699,  2257,   443,  2258,  2255,  2211,   444,
    1152,  2256,   422,  1157,  2227,  3137,  2624,  2759,  2212,  2760,
    2213,   362,  2163,  2625,  2228,  1429,  2229,   363,   364,   365,
     366,   367,   368,  3060,  2035,  3490,  2036,   651,   651,  2037,
    2148,  2348,  1629,  1351,  3181,  1429,  1688,   928,   651,  1696,
     399,  3190,  1182,  2859,    67, -1563,   445,    67,   617,   618,
     362,   551,   552,   619,   927,  2207,   363,   364,   365,   366,
     367,   368,  3176,   354, -1412,   927,  2207,   928,   740, -1412,
     927,  2002,   928,   929,   740,   424,   358,    22,   939,   359,
    2305,  2639,  2233,  2633,  2634,   354,  2636,  2829,  3255,  2640,
     360,   361,   792,   793,  1480,  1480,  -571,  2653,   358,    22,
    1348,   359,   423,   938,  3449,  2666,  1521,  1522, -1413,  -571,
    1083,  1853,   360,   361,  1084,  3684,   354,  1854, -1413,  -571,
    3610,  1853,  3611,  2252,  1085,  1480,  2445,  1865,  1086,   358,
      22,   425,   359,  1524,  1525,   651,  1526,  1527,  2269,  2275,
     787,  1348,   578,   360,   361,   788,   789,   925,  2284,  1356,
    2286,  1842,   926,  1849,  1357,  2291,  1357,  1939,  1357,  1968,
     696,  2149,  1940,   700,  1969,  3332,  2150,  2153,  1348,  2195,
    1609,  2196,  2154,  1976,  1357,  2487,  1357,  2222,  2307,  1989,
     362,  1986,  2223,  1186,  3172,  3173,   363,   364,   365,   366,
     367,   368,  2234,    83,  1348,    84,   426,  1357,  2506,  2507,
    1534,  1535,  1536,  1537,  1538,  1539,  1540,  1541,  1542,  1543,
    1544,   427,  3336,  2250,   448,  3340,  3341,   449,  1357,  3343,
     965,   651,   362,   551,   552,  1646,   798,   799,   363,   364,
     365,   366,   367,   368,  2467,  2500,  2035,  2545,  2668,  1357,
    2223,  2037,  2546,  2669,  2702,  2738,  1348,   451,     2,  2223,
    2739,     3,     4,     5,   790,   791,  1348,     6,     7,     8,
       9,  2745,  1348,    10,    11,    12,  2746,    13,    14,   478,
      15,    16,   641,    17,    18,    19,    20,    21,  1081,  1082,
    2782,  2804,   362,  1999,    23,  2783,  2805,  2374,   363,   364,
     365,   366,   367,   368,  2876,  2884,  2894,  2899,  2921,  2877,
    2669,  2223,  2669,  2922,   676,   642,   677,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,  1148,  2923,   617,   618,   806,   409,
    2223,   362,  2324,  2397,   124,  2398,   125,   363,   364,   365,
     366,   367,   368,  2962,  2441,  2972,   572,  3022,  1357,  2933,
    2739,  1348,  2223,  3097,  3104,  1348,   602,  1348,  2223,  3105,
    3118,  3335,  3120,    67,  3165,  3119,   399,  3119,  3182,  2739,
    3257,  3280,  3077,  3183,  2441,  3258,  3281,  3330,   660,  3309,
    3366,  2450,  3331,  3453,   674,  3367,  3152,   667,  3407,  1348,
     682,  3380,   579,  3408,  3429,  2870,   668,  2871,  2872,  3430,
     346,   347,  1348,  2441,  3441,   348,   349,   350,  3433,  3442,
     669,  3448,   351,   352,  3467,  2478,  1357,   353,   675,  3468,
     354,  3152,  3548,   355,  1348,  3577,  3543,  1357,   670,   356,
    3578,   671,   357,   358,    22,   362,   359,  1480,  1330,  1331,
    2275,   363,   364,   365,   366,   367,   368,   360,   361,  2752,
    3580,  3582,  2487,   672,  1480,  3581,  3581,   362,  2326,   678,
     683,   679,  2523,   363,   364,   365,   366,   367,   368,  3584,
    3636,  2530,  3641,  3670,  3585,  3119,  3674,  3642,  3119,  1181,
    3680,  3675,   701,    22,  2788,  2739,  3681,  3516,   362,  2638,
    1189,  3682,  1190,    50,   363,   364,   365,   366,   367,   368,
    2817,  3693,   354,  3700,  3703,  1986,  3119,  2558,  3701,  3704,
    2619,   684,  2833,  2812,  1976,   358,    22,  3710,   359,  1633,
     354,  1634,  3119,   806,  1635,   806,  1494,  1495,   806,   360,
     361,  2800,   685,   358,    22,  1379,   359,  1637,   688,  2321,
    2255,  1638,  2642,   806,  2256,  2646,   702,   360,   361,   923,
    2323,   924,   703,  1348,   806,  2656,  2825,   710,  2635,  1348,
    1379,  1348,   806,  2825,  1149,  2670,   815,  3232,   711,  1348,
    2674,  2675,  3480,  3241,  2637,  1639,  1231,   806,   806,  1232,
    1233,  2107,  2682,  2873,  2075,   716,  2076,   806,  1166,  1167,
    1168,  1169,  2081,  2686,  2082,  2435,   725,  2436,  1234,   551,
     658,  2691,   452,   726,  3269,   453,  3270,  3002,  3003,  3607,
    3608,   454,  3698,   727,  3699,  3052,  3053,   737,  1235,  1348,
     334,  1236,  2905,  2905,  3322,  3323,   747,  1237,  3567,  3568,
    1162,  1163,  3656,  3092,  1164,  1165,  1170,  1171,   455,  2650,
    2652,  3630,  3631,  3435,  3436,   651,  2952,  2953,   749,   900,
     750,  3643,  2721,  3706,  3707,  2994,  2995,  3504,  3505,   752,
     456,   334,   359,  2939,   117,  3316,  3317,  1370,  1371,  1238,
    1372,  1373,  1348,  3549,  3550,   758,   457,   759,  2954,   800,
     760,   801,   803,   987,   811,   802,   812,   458,   459,   460,
    2487,   810,   813,   820,  2742,   821,   825,   826,  2487,   832,
     827,   857,   863,   866,   461,  2523,   666,   867,   868,  1348,
     871,   462,   463,   464,  1239,   872,   873,   465,   878,   879,
     466,   651,   467,   882,   885,   651,   468,   886,   887,   897,
     903, -1047,  2275,   916,   917,  1348,   918,   920,   922,   921,
     930,   932,   934,  1348,   945,  2796,   651,   469,   956,   959,
     651,   960,   961,   651,   470,   964,  1989,  1240,   962,   978,
     979,   981,  2619,  3009,  2816,  1241,   471,  1986,  1989,  2821,
    2823,  2824,  1000,  2619,  1005,  2830,  1006,  1007,  2835,  1008,
    2839,  1009,  1010,  1242,   472,  1016,  1017,  1379,  1018,  1019,
    1021,  1243,   362,  1024,   988,   989,  2825,  2619,   363,   364,
     365,   366,   367,   368,  1025,  1026,  1061,  1989,  1069,  1065,
    1070,   990,   991,   369,  1072,   117,  1073,  1090,   992,   993,
    1088,  1087,  1091,  1092,   994,  1100,  1099,  1101,  1102,  1107,
    1106,   473,  1111,   995,  1113,  1126,  1116,  1244,   996,   580,
    1139,  1142,  1134,  1136,  1151,   581,  1193,  1196,  1200,  3114,
    1348,  1204,  1205,  1207,   997,  1206,  1215,  1208,  2891,  1216,
    1227,  1263,  1287,   399,   399,   399,  1288,  1295,  1296,  3128,
    1348,  1299,   582,   998,   756,  1301,  1310,  2907,  1313,  1327,
     363,   364,   365,   366,   367,   368,  1329,  1335,  1339,  1346,
    1336,   999,   762,  2914,  1352,  1361,  1368,  1362,   363,   364,
     365,   366,   367,   368,  1395,  1404,  1406,  1409,  1599,  1411,
    1412,  1413,  1431,  1414,  1423,  1424,  1432,  1433,  1452,  1453,
    1454,   583,   584,   585,  1466,  2835,  3170,  1467,  1470,  1473,
    1474,  1482,  1348,  1501,   904,  1548,  1549,  1553,   586,  1566,
    1573,  1576,  1579,  1585,  1582,   587,   588,  2275,  1580,  1586,
    1590,   589,  1600,   651,   590,  1591,  1057,  1594,  1610,  3166,
     591,  1596,  1612,  2987,  2988,   592,  3200,  2523,  1616,  1628,
    1621,  1632,  1649,  2997,  3000,  3001,  1641,   651,  1642,  1643,
    1648,   593,  1650,  1651,  2530,  3017,   651,  1655,   594,  1652,
    2812,  3018,  3191,  3192,  1653,  3021,  1656,  1658,  1659,  1660,
     595,  1666,  1671,  1672,  1673,  2812,  1685,  1677,  3034,  1689,
    1690,  2619,  1697,  1699,   596,  1698,  1707,  1347,   597,  1706,
    1708,  1710,   620,   621,  1715,  1711,  1712,  1717,  2619,  1713,
    1254,  1720,  1750,  2825,  1752,  1718,  1769,  1770,  1771,  1757,
    1782,  3067,  1725,  1387,  1772,  1748,  1749,  1379,  1781,  1399,
     622,  1751,  1753,  1387,  1379,  1768,  1778,   623,  1773,  1791,
    3078,  1774,  3082,  1348,   624,   598,  1780,  1801,  1795,  1986,
    2905,  1811,  1790,  1821,  1817,  1813,   625,  1810,  2646,  3094,
    1822,  1828,  1829,  1832,  1846,  1850,  1863,   912,  1848,   626,
    1866,  1840,  -576,  1348,  1852,  1879,   627,  1859,  1873,  1880,
    1867,  1857,  1888,  1889,  1890,  1878,  2954,  1891,  1893,  1908,
    1894,  3124,  1904,  1858,  3126,  3324,  1886,  1876,  1877,  1869,
    1870,  1905,  1922,  1924,  1926,  1927,  3138,  1938,  1933,  1937,
    1941,  1942,  1947,  1951,  1949,  1952,  1960,  1962,  1967,   628,
    1993,  1995,   629,  2013,  3359,  2014,  2017,  1953,  2019,   651,
    2028,  2043,   630,  1961,  2011,  2045,  1528,  1528,  1528,  1528,
    1528,  1528,  1528,  1528,  1528,  1528,  1528,  1528,  2009,  2012,
    2020,  2010,  2056,  2016,   631,  2021,   432,  2022,  2027,  3360,
    2038,  2812,   651,   651,  1570,  2058,   632,  2061,  2060,  2063,
    2089,  2094,  2095,  2104,  2096,  2097,  2109,  2523,   938,  2111,
    2103,  2108,  1742,   633,  2132,   938,  2134,  2113,  2137,   433,
    2121,  3409,  2126,  2124,  2151,  2157,  2131,  2128,  2159,  2135,
    2160,  2825,  2825,   651,  2175,   634,  2165,  1603,  2177,   399,
    2176,  2179,  2186,  2182,  2190,  2188,  2197,   651,  2193,  2194,
    2199,  2201,  2220,  2619,   651,  2221,  3224,  2236,  2619,  2214,
    2224,  2835,  3229,  2230,  2231,  3233,  2241,  2619,   434,  2247,
    1429,  1885,  2239,  2248,  3243,  1989,  2243,  3245,  2253,  2261,
    2264,  2839,  2263,  2278,  2282,   435,  1095,  3421,  2279,   551,
     552,  2283,  3170,   437,  2148,  1316,  2285,  2289,   438,  3260,
    2292,  2297,  2301,  2309,  2314,  2303,  2315,   439,  2329,  2330,
    2331,  2333,   440,  2332,  2341,  2350,  2891,  3278,  2334,  2335,
    2336,  2344,  2349,  2351,  2354,  2352,  2355,  2360,  2364,  2368,
    2369,  2370,  3289,  3290,  2083,   441,  2375,  3451,  2377,  2378,
    2379,  2381,  2382,  2407,  2812,  2390,  2392,   442,  2380,  2170,
    2388,  2393,  2391,  2395,  1317,  2421,  2413,  2424,  2418,   651,
    2425,   443,  2451,  2835,  2454,   444,  2394,  2462,  2455,  2457,
    2470,  2468,  2464,  2399,  2402,  2501,  2417,  2404,  2410,   651,
    2441,  2480,  2476,  2440,  2446,  2499,   938,  3338,  2447,   938,
     938,  2477,  2505,   938,  3000,  3345,  2491,  2479,  2492,  3487,
    2504,  2508,  2514,  3324,  2526,  2533,  2534,  2535,  2536,  2538,
    2541,  2544,   445,  2556,  2542,  3518,  3365,  2629,  2620,  2641,
    2654,   651,   651,  3529,  3529,  3536,  3359,  1989,  2649,  2223,
    2647,  2150,  2657,  2619,  1784,  2648,  2619,  2812,  2660,  2671,
    2658,  2672,  2690,  1784,  2632,  2619,  2619,  2678,  2676,  2677,
    2692,  2400,  2680,  2693,  2694,  2697,  2695,  2698,  2701,  2401,
    2704,  2708,  2712,  1348,  2724,  2727,  3401,  2710,  2711,  1348,
    1830,  2719,  2722,  2728,  3405,  3406,  2731,   651,   666,  2730,
    2218,  2744,  2747,  2755,  3411,  2762,  2763,  2750,  2764,  2766,
    3413,  2790,  1348,  2791,  2793,  2784,  2794,  2797,  2808,  2806,
    2809,  2818,  2802,  2828,  2861,  2841,  2812,  2840,  2842,  2843,
    2867,  2878,  2886,  2852,  3428,  2844,  2862,  2892,  2893,  2845,
    2846,  2847,  2848,  2849,  2850,  2857,  2905,   651,  2863,  2895,
    2896,  2897,  2898,  2902,  2908,  2909,  2910,  2913,  1871,  2885,
    2911,  2918,  3529,  2912,  2916,  2920,  3536,  2924,  2929,  2932,
    2935,  1763,  2942,  2948,  2949,  2960,  2957,   938,  2975,  2996,
    2990,  2992,  1348,   399,   399,  2958,   399,  2969,  3007,   399,
     651,  3008,  3010,  3466,  3013,  3015,  3036,  3019,  3023,  3024,
    3042,  3039,  2811,  3047,  3048,  3055,  3056,  3074,  3059,   651,
    3061,  1056,  2835,  3062,  2572,  1989,  2905,  2619,  3065,  3068,
     346,   347,  3066,  3087,  3070,   348,   349,   350,  2839,  3069,
    2148,  3075,   351,   352,  3101,  3079,  2487,   353,  3095,  3102,
     354,  3112,  3106,   355,  3111,  3113,  1680,  2905,  3123,   356,
    3494,  3495,   357,   358,    22,  3125,   359,  3141,  3136,  3145,
    3152,  3155,  3163, -1209,  3164,  3177,  3174,   360,   361,  3188,
    3175,  3178,  3187,  2905,  3193,  3194,  3197,  2777,  3204,  3203,
    3515,   938,  3205,  3216,  3208,  3212,  1348,  3223,  3213,  1348,
    -517,  3227,  3230,  3210,  3240,  3201,  3261,  3253,  3263,     2,
    3540,  3264,     3,     4,     5,  1989,  3267,  3211,     6,     7,
       8,     9,  3279,  3283,    10,    11,    12,  3552,    13,    14,
    3215,    15,    16,  3284,    17,    18,    19,    20,    21,  3246,
    3286,  3288,  3291,  3300,  3302,    23,   651,  3303,  3306,  3327,
    1758,  3347,  3301,  3314,  3350,  3339,  3351,  3362,  3370,  3368,
    1348,  3373,  3371,  3376,  1973,  3372,  3377,  1348,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,  3378,  3381,  3383,  3389,  3390,
    3391,  3392,  3397,  3399,  3404,  3394,  3410,  3393,  3400,  3402,
    3599,  3416,  3419,  3417,  3418,  3422,  3423,  3420,  3437,  3454,
    3424,  3426,  3427,   938,   938,  3438,  3450,  3462,  3465,  1348,
    3469,  3463,  3464,  3474,  3471,  3472,  3476,  3622,  3623,  3483,
    3473,  3486,  3513,  1989,  3496,  3522,  3526,  3538,  3511,  3541,
    3512,  3545,  3553,  3547,  3554,  3551,  3559,  2275,  -571,  3586,
    2062,  3587,  3597,  3589,  3575,   938,  2067,  3572,  3573,  3576,
    3606,  3598,  3603,  3609,  3617,  1989,  3634,  3635,  3637,  3644,
    3646,  3645,  3655,  3676,  3648,  3652,  3668,  3667,  3669,  3677,
    3692,  3697,   106,  3649,  1172,  1348,  1175,  1177,   733,  1173,
     343,   421,  1624,   335,  1174,  1192,   809,  1584,  1176,  1348,
     225,   761,  1488,   977,   227,   399,   822,   399,   399,  1094,
     653,  2703,  1064,  2238,  1481,  2944,  1348,  2743,  2977,  2943,
    2681,  1257,  2098,  1348,     2,   346,   347,     3,     4,     5,
     348,   349,   350,     6,     7,     8,     9,   351,   352,    10,
      11,    12,   353,    13,    14,   354,    15,    16,   355,    17,
      18,    19,    20,    21,   356,  1260,  1261,   357,   358,    22,
      23,   359,  3539,  3361,  2110,  3103,  3414,  2888,  3277,  3093,
    1311,  1788,   360,   361,  3470,  3369,  3502,  1719,  3412,  1950,
    3287,  3488,  2420,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
    2409,  2347,  2696,  3299,  3298,  2917,   599,  2276,  2205,  2181,
    3638,  1896,  2966,  2973,  3016,  3446,  2785,  3605,    50,  2205,
    3447,  2277,   362,  2189,   687,  1931,  2266,  1569,   363,   364,
     365,   366,   367,   368,  1112,  2191,  3521,  3657,  3579,  3683,
    3705,  3344,  1397,   369,  3530,   117,  3619,  3620,     3,     4,
       5,  3621,  3537,  1871,     6,     7,  3198,     9,  3012,  3196,
      10,    11,  2299,  2296,    13,    14,  1369,  3510,    16,  2540,
    3202,    18,    19,    20,    21,  3319,  2251,  1825,  1020,  2185,
      22,    23,  1826,  3318,  3509,  2860,  2300,  2192,  3080,  2310,
    2819,  3403,  2271,  3251,  1570,  1491,  3221,  1490,  3044,  3220,
    3590,  2405,  2443,  1764,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,    35,    36,    37,    38,    39,
      40,  1603,  1779,  2403,  2386,   117,  1973,  1344,  3310,  2444,
    2427,  2684,  3086,  2631,  3149,  3313,  2726,  2941,  3489,     0,
       0,  1887,     0,   399,     0,     0,     0,  1871,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     2,
     346,   347,     3,     4,     5,   348,   349,   350,     6,     7,
       8,     9,   351,   352,    10,    11,    12,   353,    13,    14,
     354,    15,    16,   355,    17,    18,    19,    20,    21,   356,
       0,     0,   357,   358,    22,    23,   359,     0,  1592,  1784,
       0,     0,     0,     0,     0,     0,     0,   360,   361,  2359,
       0,     0,     0,     0,     0,  2362,     0,     0,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    50,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,  1784,     0,     0,     0,  1784,     0,
    1871,     0,     0,     0,     0,     0,     0,   362,     0,     0,
       0,     0,     0,   363,   364,   365,   366,   367,   368,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   369,   370,
     117,     0,  2456,     0,     0,     3,     4,     5,     0,     0,
       0,     6,     7,     0,     9,  2466,     0,    10,    11,     0,
       0,    13,    14,     0,     0,    16,     0,     0,    18,    19,
      20,    21,     0,     0,     0,     0,     0,  2483,    23,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   452,
       0,     0,   453,  2271,     0,     0,     0,     0,   454,     0,
       0,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,     0,     0,
      41,    42,    43,     0,  2527,     0,     0,     0,    44,    45,
      46,    47,    48,    49,     0,     0,     0,     0,    51,     0,
       0,     0,     0,     0,     0,    52,     0,   456,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   741,     0,     0,
    2557,     0,     0,  1097,     0,     0,     0,  1973,     0,     0,
       0,     0,     0,     0,     0,   459,   460,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   461,     0,     0,     0,     0,     0,     0,   462,   463,
     464,     0,     0,     0,   465,     0,  2362,     0,     0,   467,
       0,     0,  1871,   468,  2362,     0,     0,     0, -1047,     0,
       0,     0,  2673,     3,     4,     5,     0,     0,     0,     6,
       7,     0,     9,     0,   469,    10,    11,     0,     0,    13,
      14,   470,     0,    16,     0,     0,    18,    19,    20,    21,
       0,     0,   362,   471,     0,     0,    23,     0,   363,   364,
     365,   366,   367,   368,     0,     0,     0,     0,     0,     0,
       0,   472,  1871,   369,   808,   117,     0,     0,     0,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,     0,     0,    41,    42,
      43,     0,     0,     0,     0,     0,    44,    45,    46,    47,
      48,    49,     0,     0,     0,     0,     0,     0,   473,     0,
       0,     0,     0,     0,     0,  2734,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     3,     4,     5,     0,     0,     0,     6,     7,     0,
       9,     0,     0,    10,    11,     0,     0,    13,    14,     0,
       0,    16,  2753,     0,    18,    19,    20,    21,     0,     0,
       0,     0,     0,     0,    23,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,  2271,     0,     0,  2789,     0,
       0,     0,     0,     0,     0,     0,  1871,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,     0,     0,    41,    42,    43,     0,
       0,     0,     0,     0,    44,    45,    46,    47,    48,    49,
       3,     4,     5,     0,     0,     0,     6,     7,     0,     9,
       0,     0,    10,    11,     0,     0,    13,    14,     0,     0,
      16,     0,     0,    18,    19,    20,    21,   336,     0,     0,
       0,     0,     0,    23,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    24,    25,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      38,    39,    40,  1871,     0,    41,    42,    43,     0,     0,
       0,     0,     0,    44,    45,    46,    47,    48,    49,     0,
       0,     0,     0,  2901,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   105,     0,
       0,     1,     2,     0,     0,     3,     4,     5,     0,     0,
       0,     6,     7,     8,     9,     0,     0,    10,    11,    12,
       0,    13,    14,     0,    15,    16,     0,    17,    18,    19,
      20,    21,     0,     0,     0,     0,     0,    22,    23,     0,
       0,     0,     0,     0,     0,  2961,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    2271,    24,    25,    26,    27,    28,    29,    30,    31,    32,
      33,    34,    35,    36,    37,    38,    39,    40,     0,     0,
      41,    42,    43,     0,     0,     0,     0,     0,    44,    45,
      46,    47,    48,    49,     0,   342,    50,  2527,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  3033,     0,     0,     0,     0,     0,     0,     1,     2,
       0,     0,     3,     4,     5,     0,     0,     0,     6,     7,
       8,     9,     0,     0,    10,    11,    12,     0,    13,    14,
       0,    15,    16,     0,    17,    18,    19,    20,    21,     0,
       0,     0,     0,     0,    22,    23,     0,     0,     0,     0,
       0,     0,     0,  3076,     0,     0,  3083,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39,    40,     0,  3107,    41,    42,    43,
       0,     0,     0,   739,     0,    44,    45,    46,    47,    48,
      49,     0,     0,    50,     3,     4,     5,     0,     0,     0,
       6,     7,     0,     9,     0,     0,    10,    11,     0,     0,
      13,    14,   354,     0,    16,     0,     0,    18,    19,    20,
      21,     0,     0,     0,     0,   358,    22,    23,   359,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   360,
     361,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,     3,     4,     5,
       0,     0,   746,     6,     7,     0,     9,     0,     0,    10,
      11,     0,     0,    13,    14,     0,     0,    16,     0,     0,
      18,    19,    20,    21,     0,     0,     0,     0,     0,    22,
      23,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
       0,     0,     0,     0,     3,     4,     5,  3076,     0,     0,
       6,     7,     0,     9,     0,     0,    10,    11,     0,     0,
      13,    14,     0,     0,    16,    51,     0,    18,    19,    20,
      21,     0,    52,     0,     0,     0,    22,    23,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40,     3,     4,     5,
       0,     0,     0,     6,     7,     0,     9,     0,     0,    10,
      11,     0,     0,    13,    14,     0,     0,    16,     0,     0,
      18,    19,    20,    21,     0,     0,     0,     0,     0,     0,
      23,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    3337,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,    24,    25,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,    38,    39,    40,
       0,     0,    51,     0,     0,     0,     0,     0,     0,    52,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  3398,     0,     0,     0,
       0,     0,  3083,     3,     4,     5,     0,     0,     0,     6,
       7,     0,     9,     0,     0,    10,    11,     0,     0,    13,
      14,     0,     0,    16,     0,  3107,    18,    19,    20,    21,
       0,     0,     0,     0,     0,     0,    23,     0,     0,     0,
       0,     0,     0,     0,   362,     0,     0,     0,     0,     0,
     363,   364,   365,   366,   367,   368,     0,     0,     0,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,     3,     4,     5,     0,
       0,     0,     6,     7,     0,     9,     0,     0,    10,    11,
       0,     0,    13,    14,     0,  3459,    16,     0,     0,    18,
      19,    20,    21,     0,     0,     0,     0,     0,     0,    23,
       0,     0,     0,     0,     0,     0,     0,   814,  1183,   815,
       0,     0,     0,     0,    52,     0,     0,     0,     0,     0,
       0,     0,    24,    25,    26,    27,    28,    29,    30,    31,
      32,    33,    34,    35,    36,    37,    38,    39,    40,     3,
       4,     5,     0,     0,     0,     6,     7,     0,     9,     0,
       0,    10,    11,     0,     0,    13,    14,     0,     0,    16,
       0,     0,    18,    19,    20,    21,     0,     0,     0,     0,
       0,     0,    23,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  3514,   814,     0,   815,     0,     0,  3520,
       0,    52,  3459,     0,     0,    24,    25,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,    38,
      39,    40,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  3574,     0,     0,     0,  1149,  1183,   815,
    3459,     0,     0,     0,    52,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   479,     0,
       0,     0,     0,   480,   481,     0,     0,   482,   483,     0,
       0,     0,     0,     0,   484,   485,     0,   486,   487,     0,
     488,     0,   489,     0,     0,     0,     0,     0,   490,     0,
       0,     0,  3459,     0,     0,   491,     0,   492,   493,     0,
       0,     0,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,     0,     0,   496,     0,   497,   498,
    2271,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     499,   500,   501,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,     0,   509,     0,  3659,     0,
       0,   510,     0,  1149,     0,   815,     0,     0,   511,     0,
      52,   512,  3659,     0,     0,   513,   514,   515,   516,     0,
       0,     0,     0,     0,     0,   517,     0,     0,     0,  3659,
     518,     0,     0,     0,   519,     0,  3659,   520,     0,     0,
     521,     0,     0,     0,   522,   523,   524,   525,     0,     0,
     526,     0,     0,   527,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   528,   529,   530,   531,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   532,     0,     0,
       0,     0,     0,    52,     0,     0,   533,     0,   534,     0,
       0,     0,     0,     0,   535,   536,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   537,   538,
       0,     0,   539,   540,     0,     0,     0,     0,     0,     0,
       0,   541,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   542,     0,     0,     0,     0,   543,     0,
     544,     0,     0,     0,     0,     0,     0,     0,   545,     0,
    1644,   546,   547,   548,   549,   550,   551,   552,     0,     0,
       0,     0,     0,   553,     0,   554,  3352,     0,     0,     0,
       0,     0,     0,   555,   479,     0,     0,   556,     0,   480,
     481,     0,     0,   482,   483,  3353,     0,     0,     0,     0,
     484,   485,  3354,   486,   487,     0,   488,     0,   489,     0,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
       0,   491,     0,   492,   493,     0,     0,     0,     0,     0,
       0,     0,     0,   494,     0,   495,     0,     0,     0,     0,
       0,     0,   496,     0,   497,   498,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,   501,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,     0,   509,     0,     0,     0,     0,   510,     0,     0,
       0,     0,     0,     0,   511,     0,     0,   512,     0,     0,
       0,   513,   514,   515,   516,     0,     0,     0,     0,     0,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
     522,   523,   524,   525,     0,     0,   526,     0,     0,   527,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     528,   529,   530,   531,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   532,     0,     0,     0,     0,     0,     0,
       0,     0,   533,     0,   534,     0,     0,     0,     0,     0,
     535,   536,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   537,   538,     0,     0,   539,   540,
       0,     0,     0,     0,     0,     0,     0,   541,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  3531,
       0,     0,     0,     0,   543,     0,   544,     0,     0,     0,
       0,     0,     0,   142,   545,     0,     0,   546,   547,   548,
     549,   550,   551,   552,     0,     0,     0,     0,     0,   553,
     143,   554,  3352,   144,   145,     0,   146,     0,     0,   555,
     147,     0,     0,   556,     0,   148,   149,   150,   151,     0,
       0,  3353,   152,     0,   153,   154,     0,     0,     0,     0,
       0,     0,   155,     0,     0,     0,   156,     0,     0,     0,
     157,     0,     0,   158,     0,     0,     0,     0,     0,   159,
       0,     0,     0,     0,     0,     0,   160,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   161,   162,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   163,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   164,     0,   165,   166,     0,   167,
       0,   168,   169,     0,     0,   170,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   171,     0,   172,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   173,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   174,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   175,
     176,     0,     0,     0,     0,   177,     0,   479,     0,     0,
       0,     0,   480,   481,   178,     0,   482,   483,     0,     0,
     179,   180,     0,     0,   899,     0,   486,   487,     0,   488,
       0,   489,     0,     0,     0,     0,   181,   490,     0,     0,
       0,     0,     0,  1381,   491,     0,   492,   493,     0,     0,
       0,     0,     0,     0,     0,     0,   494,     0,   495,     0,
     182,     0,   183,     0,   184,   185,     0,   497,   498,     0,
     186,     0,     0,     0,     0,   187,     0,     0,     0,     0,
       0,     0,   188,     0,     0,   189,     0,     0,     0,   499,
     500,     0,   502,     0,   503,     0,   504,     0,   505,   506,
     507,     0,   508,     0,     0,     0,     0,     0,     0,     0,
     510,     0,     0,     0,     0,     0,     0,   511,     0,     0,
    1382,     0,     0,     0,   513,   514,   515,   516,     0,     0,
       0,     0,     0,     0,   517,     0,     0,     0,     0,   518,
       0,     0,     0,   519,     0,     0,   520,     0,     0,   521,
       0,     0,     0,     0,   523,   524,     0,     0,     0,   526,
       0,     0,   527,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   528,   529,   530,   531,     0,     0,     0,
       0,     0,     0,     0,     0,  1383,   532,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   534,     0,     0,
       0,     0,     0,     0,   536,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   537,   538,     0,
     479,     0,     0,     0,     0,   480,   481,     0,     0,   482,
     483,     0,     0,     0,     0,     0,     0,   899,     0,   486,
     487,     0,   488,     0,   489,     0,  1400,     0,     0,     0,
     490,     0,     0,     0,     0,     0,  1381,   491,     0,   492,
     493,     0,     0,     0,     0,   551,   552,     0,     0,   494,
       0,   495,     0,     0,     0,     0,     0,     0,     0,  1384,
     497,   498,   555,     0,     0,     0,  1385,  1386,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   499,   500,     0,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,     0,     0,     0,
       0,     0,     0,   510,     0,     0,     0,     0,     0,     0,
     511,     0,     0,  1382,     0,     0,     0,   513,   514,   515,
     516,     0,     0,     0,     0,     0,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,     0,     0,     0,     0,   523,   524,     0,
       0,     0,   526,     0,     0,   527,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   528,   529,   530,   531,
       0,     0,     0,     0,     0,     0,     0,     0,  1383,   532,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     534,     0,     0,     0,     0,     0,     0,   536,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     537,   538,     0,   479,     0,     0,     0,     0,   480,   481,
       0,     0,   482,   483,     0,     0,     0,     0,     0,     0,
     899,     0,   486,   487,     0,   488,     0,   489,     0,  2216,
       0,     0,     0,   490,     0,     0,     0,     0,     0,  1381,
     491,     0,   492,   493,     0,     0,     0,     0,   551,   552,
       0,     0,   494,     0,   495,     0,     0,     0,     0,     0,
       0,     0,  1384,   497,   498,   555,     0,     0,     0,  1385,
    1386,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   499,   500,     0,   502,     0,
     503,     0,   504,     0,   505,   506,   507,     0,   508,     0,
       0,     0,     0,     0,     0,     0,   510,     0,     0,     0,
       0,     0,     0,   511,     0,     0,  1382,     0,     0,     0,
     513,   514,   515,   516,     0,     0,     0,     0,     0,     0,
     517,     0,     0,     0,     0,   518,     0,     0,     0,   519,
       0,     0,   520,     0,     0,   521,     0,     0,     0,     0,
     523,   524,     0,     0,     0,   526,     0,     0,   527,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   528,
     529,   530,   531,     0,     0,     0,     0,     0,     0,     0,
       0,  1383,   532,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   534,     0,     0,     0,     0,     0,     0,
     536,     0,     0,     0,     0,     0,   479,  1374,     0,     0,
       0,   480,   481,   537,   538,   482,   483,     0,     0,     0,
       0,     0,   484,   485,     0,   486,   487,     0,   488,     0,
     489,     0,     0,     0,     0,     0,   490,     0,     0,     0,
       0,     0,     0,   491,     0,   492,   493,     0,  1375,     0,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,   551,   552,     0,   496,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,  1384,     0,     0,   555,     0,
       0,     0,  1385,  1386,     0,     0,     0,     0,   499,   500,
     501,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,   643,   509,     0,     0,     0,     0,   510,
       0,     0,     0,     0,     0,     0,   511,     0,     0,   512,
       0,     0,     0,   513,   514,   515,   516,     0,     0,     0,
       0,     0,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,   522,   523,   524,   525,   644,     0,   526,     0,
       0,   527,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   528,   529,   530,   531,     0,     0,     0,     0,
       0,     0,     0,     0,   645,   532,     0,     0,     0,     0,
       0,     0,     0,     0,   533,     0,   534,     0,     0,     0,
       0,     0,   535,   536,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   537,   538,     0,     0,
     539,   540,     0,     0,     0,     0,     0,     0,     0,   541,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   542,  1376,     0,     0,  1377,   543,     0,   544,     0,
       0,     0,     0,     0,     0,     0,   545,     0,     0,   546,
     547,   548,   549,   550,   551,   552,     0,     0,     0,     0,
       0,   553,     0,   554,   479,  1374,     0,     0,     0,   480,
     481,   555,     0,   482,   483,   556,     0,     0,     0,     0,
     484,   485,     0,   486,   487,     0,   488,     0,   489,     0,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
       0,   491,     0,   492,   493,     0,  1375,     0,     0,     0,
       0,     0,     0,   494,     0,   495,     0,     0,     0,     0,
       0,     0,   496,     0,   497,   498,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,   501,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,   643,   509,     0,     0,     0,     0,   510,     0,     0,
       0,     0,     0,     0,   511,     0,     0,   512,     0,     0,
       0,   513,   514,   515,   516,     0,     0,     0,     0,     0,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
     522,   523,   524,   525,   644,     0,   526,     0,     0,   527,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     528,   529,   530,   531,     0,     0,     0,     0,     0,     0,
       0,     0,   645,   532,     0,     0,     0,     0,     0,     0,
       0,     0,   533,     0,   534,     0,     0,     0,     0,     0,
     535,   536,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   537,   538,     0,     0,   539,   540,
       0,     0,     0,     0,     0,     0,     0,   541,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   542,
    3479,     0,     0,  1377,   543,     0,   544,     0,     0,     0,
       0,     0,     0,     0,   545,     0,     0,   546,   547,   548,
     549,   550,   551,   552,     0,     0,     0,     0,   479,   553,
       0,   554,     0,   480,   481,     0,     0,   482,   483,   555,
       0,     0,     0,   556,   484,   485,     0,   486,   487,     0,
     488,     0,   489,     0,     0,     0,     0,     0,   490,     0,
       0,     0,     0,     0,     0,   491,     0,   492,   493,     0,
       0,     0,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,     0,     0,   496,     0,   497,   498,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     499,   500,   501,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,   643,   509,     0,     0,     0,
       0,   510,     0,     0,     0,     0,     0,     0,   511,     0,
       0,   512,     0,     0,     0,   513,   514,   515,   516,     0,
       0,     0,     0,     0,     0,   517,     0,     0,     0,     0,
     518,     0,     0,     0,   519,     0,     0,   520,     0,     0,
     521,     0,     0,     0,   522,   523,   524,   525,   644,     0,
     526,     0,     0,   527,     0,     0,     0,     0,     0,     0,
       0,   904,     0,     0,   528,   529,   530,   531,     0,     0,
       0,     0,     0,     0,     0,     0,   645,   532,     0,     0,
       0,     0,     0,     0,     0,     0,   533,     0,   534,     0,
       0,     0,     0,     0,   535,   536,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   537,   538,
       0,     0,   539,   540,     0,     0,     0,     0,     0,     0,
       0,   541,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   542,  3583,     0,     0,     0,   543,     0,
     544,     0,     0,     0,     0,     0,     0,     0,   545,     0,
       0,   546,   547,   548,   549,   550,   551,   552,     0,     0,
       0,     0,   479,   553,     0,   554,     0,   480,   481,     0,
       0,   482,   483,   555,     0,     0,     0,   556,   484,   485,
       0,   486,   487,     0,   488,     0,   489,     0,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,     0,   491,
       0,   492,   493,     0,     0,     0,     0,     0,     0,     0,
       0,   494,     0,   495,     0,     0,     0,     0,     0,     0,
     496,     0,   497,   498,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   499,   500,   501,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,   643,
     509,     0,     0,     0,     0,   510,     0,     0,     0,     0,
       0,     0,   511,     0,     0,   512,     0,     0,     0,   513,
     514,   515,   516,     0,     0,     0,     0,     0,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,   522,   523,
     524,   525,   644,     0,   526,     0,     0,   527,     0,     0,
       0,     0,     0,     0,     0,   904,     0,     0,   528,   529,
     530,   531,     0,     0,     0,     0,     0,     0,     0,     0,
     645,   532,     0,     0,     0,     0,     0,     0,     0,     0,
     533,     0,   534,     0,     0,     0,     0,     0,   535,   536,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   537,   538,     0,     0,   539,   540,     0,     0,
       0,     0,     0,     0,     0,   541,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   542,     0,     0,
       0,     0,   543,     0,   544,     0,     0,     0,     0,     0,
       0,     0,   545,     0,     0,   546,   547,   548,   549,   550,
     551,   552,     0,     0,     0,     0,   479,   553,     0,   554,
       0,   480,   481,     0,     0,   482,   483,   555,     0,     0,
       0,   556,   484,   485,     0,   486,   487,     0,   488,     0,
     489,     0,     0,     0,     0,     0,   490,     0,     0,     0,
       0,     0,     0,   491,     0,   492,   493,     0,     0,     0,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,     0,     0,     0,   496,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   499,   500,
     501,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,   643,   509,     0,     0,     0,     0,   510,
       0,     0,     0,     0,     0,     0,   511,     0,     0,   512,
       0,     0,     0,   513,   514,   515,   516,     0,     0,     0,
       0,     0,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,   522,   523,   524,   525,   644,     0,   526,     0,
       0,   527,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   528,   529,   530,   531,     0,     0,     0,     0,
       0,     0,     0,     0,   645,   532,     0,     0,     0,     0,
       0,     0,     0,     0,   533,     0,   534,     0,     0,     0,
       0,     0,   535,   536,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   537,   538,     0,     0,
     539,   540,     0,     0,     0,     0,     0,     0,     0,   541,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   542,  1366,     0,     0,     0,   543,     0,   544,     0,
       0,     0,     0,     0,     0,     0,   545,     0,     0,   546,
     547,   548,   549,   550,   551,   552,     0,     0,     0,     0,
     479,   553,     0,   554,     0,   480,   481,     0,     0,   482,
     483,   555,     0,     0,     0,   556,   484,   485,     0,   486,
     487,     0,   488,     0,   489,     0,     0,     0,     0,     0,
     490,     0,     0,     0,     0,     0,     0,   491,     0,   492,
     493,     0,     0,     0,     0,     0,     0,     0,     0,   494,
       0,   495,     0,     0,     0,     0,     0,     0,   496,     0,
     497,   498,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   499,   500,   501,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,   643,   509,     0,
       0,     0,     0,   510,     0,     0,     0,     0,     0,     0,
     511,     0,     0,   512,     0,     0,     0,   513,   514,   515,
     516,     0,     0,     0,     0,     0,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,     0,     0,     0,   522,   523,   524,   525,
     644,     0,   526,     0,     0,   527,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   528,   529,   530,   531,
       0,     0,     0,     0,     0,     0,     0,     0,   645,   532,
       0,     0,     0,     0,     0,     0,     0,     0,   533,     0,
     534,     0,     0,     0,     0,     0,   535,   536,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     537,   538,     0,     0,   539,   540,     0,     0,     0,     0,
       0,     0,     0,   541,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   542,     0,     0,     0,  1843,
     543,     0,   544,     0,     0,     0,     0,     0,     0,     0,
     545,     0,     0,   546,   547,   548,   549,   550,   551,   552,
       0,     0,     0,     0,   479,   553,     0,   554,     0,   480,
     481,     0,     0,   482,   483,   555,     0,     0,     0,   556,
     484,   485,     0,   486,   487,     0,   488,     0,   489,     0,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
       0,   491,     0,   492,   493,     0,     0,     0,     0,     0,
       0,     0,     0,   494,     0,   495,     0,     0,     0,     0,
       0,     0,   496,     0,   497,   498,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,   501,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,   643,   509,     0,     0,     0,     0,   510,     0,     0,
       0,     0,     0,     0,   511,     0,     0,   512,     0,     0,
       0,   513,   514,   515,   516,     0,     0,     0,     0,     0,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
     522,   523,   524,   525,   644,     0,   526,     0,     0,   527,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     528,   529,   530,   531,     0,     0,     0,     0,     0,     0,
       0,     0,   645,   532,     0,     0,     0,     0,     0,     0,
       0,     0,   533,     0,   534,     0,     0,     0,     0,     0,
     535,   536,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   537,   538,     0,     0,   539,   540,
       0,     0,     0,     0,     0,     0,     0,   541,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   542,
    1882,     0,     0,     0,   543,     0,   544,     0,     0,     0,
       0,     0,     0,     0,   545,     0,     0,   546,   547,   548,
     549,   550,   551,   552,     0,     0,     0,     0,   479,   553,
       0,   554,     0,   480,   481,     0,     0,   482,   483,   555,
       0,     0,     0,   556,   484,   485,     0,   486,   487,     0,
     488,     0,   489,     0,     0,     0,     0,     0,   490,     0,
       0,     0,     0,     0,     0,   491,     0,   492,   493,     0,
       0,     0,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,     0,     0,   496,     0,   497,   498,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     499,   500,   501,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,   643,   509,     0,     0,     0,
       0,   510,     0,     0,     0,     0,     0,     0,   511,     0,
       0,   512,     0,     0,     0,   513,   514,   515,   516,     0,
       0,     0,     0,     0,     0,   517,     0,     0,     0,     0,
     518,     0,     0,     0,   519,     0,     0,   520,     0,     0,
     521,     0,     0,     0,   522,   523,   524,   525,   644,     0,
     526,     0,     0,   527,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   528,   529,   530,   531,     0,     0,
       0,     0,     0,     0,     0,     0,   645,   532,     0,     0,
       0,     0,     0,     0,     0,     0,   533,     0,   534,     0,
       0,     0,     0,     0,   535,   536,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   537,   538,
       0,     0,   539,   540,     0,     0,     0,     0,     0,     0,
       0,   541,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   542,  2202,     0,     0,     0,   543,     0,
     544,     0,     0,     0,     0,     0,     0,     0,   545,     0,
       0,   546,   547,   548,   549,   550,   551,   552,     0,     0,
       0,     0,   479,   553,     0,   554,     0,   480,   481,     0,
       0,   482,   483,   555,     0,     0,     0,   556,   484,   485,
       0,   486,   487,     0,   488,     0,   489,     0,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,     0,   491,
       0,   492,   493,     0,     0,     0,     0,     0,     0,     0,
       0,   494,     0,   495,     0,     0,     0,     0,     0,     0,
     496,     0,   497,   498,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   499,   500,   501,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,   643,
     509,     0,     0,     0,     0,   510,     0,     0,     0,     0,
       0,     0,   511,     0,     0,   512,     0,     0,     0,   513,
     514,   515,   516,     0,     0,     0,     0,     0,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,   522,   523,
     524,   525,   644,     0,   526,     0,     0,   527,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   528,   529,
     530,   531,     0,     0,     0,     0,     0,     0,     0,     0,
     645,   532,     0,     0,     0,     0,     0,     0,     0,     0,
     533,     0,   534,     0,     0,     0,     0,     0,   535,   536,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   537,   538,     0,     0,   539,   540,     0,     0,
       0,     0,     0,     0,     0,   541,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   542,  2732,     0,
       0,     0,   543,     0,   544,     0,     0,     0,     0,     0,
       0,     0,   545,     0,     0,   546,   547,   548,   549,   550,
     551,   552,     0,     0,     0,     0,   479,   553,     0,   554,
       0,   480,   481,     0,     0,   482,   483,   555,     0,     0,
       0,   556,   484,   485,     0,   486,   487,     0,   488,     0,
     489,     0,     0,     0,     0,     0,   490,     0,     0,     0,
       0,     0,     0,   491,     0,   492,   493,     0,     0,     0,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,     0,     0,     0,   496,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   499,   500,
     501,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,   643,   509,     0,     0,     0,     0,   510,
       0,     0,     0,     0,     0,     0,   511,     0,     0,   512,
       0,     0,     0,   513,   514,   515,   516,     0,     0,     0,
       0,     0,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,   522,   523,   524,   525,   644,     0,   526,     0,
       0,   527,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   528,   529,   530,   531,     0,     0,     0,     0,
       0,     0,     0,     0,   645,   532,     0,     0,     0,     0,
       0,     0,     0,     0,   533,     0,   534,     0,     0,     0,
       0,     0,   535,   536,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   537,   538,     0,     0,
     539,   540,     0,     0,     0,     0,     0,     0,     0,   541,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   542,     0,     0,     0,     0,   543,     0,   544,     0,
       0,     0,  2831,     0,     0,     0,   545,     0,     0,   546,
     547,   548,   549,   550,   551,   552,     0,     0,     0,     0,
     479,   553,     0,   554,     0,   480,   481,     0,     0,   482,
     483,   555,     0,     0,     0,   556,   484,   485,     0,   486,
     487,     0,   488,     0,   489,     0,     0,     0,     0,     0,
     490,     0,     0,     0,     0,     0,     0,   491,     0,   492,
     493,     0,     0,     0,     0,     0,     0,     0,     0,   494,
       0,   495,     0,     0,     0,     0,     0,     0,   496,     0,
     497,   498,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   499,   500,   501,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,   643,   509,     0,
       0,     0,     0,   510,     0,     0,     0,     0,     0,     0,
     511,     0,     0,   512,     0,     0,     0,   513,   514,   515,
     516,     0,     0,     0,     0,     0,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,     0,     0,     0,   522,   523,   524,   525,
     644,     0,   526,     0,     0,   527,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   528,   529,   530,   531,
       0,     0,     0,     0,     0,     0,     0,     0,   645,   532,
       0,     0,     0,     0,     0,     0,     0,     0,   533,     0,
     534,     0,     0,     0,     0,     0,   535,   536,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     537,   538,     0,     0,   539,   540,     0,     0,     0,     0,
       0,     0,     0,   541,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   542,     0,     0,     0,     0,
     543,     0,   544,     0,     0,     0,     0,     0,     0,     0,
     545,     0,     0,   546,   547,   548,   549,   550,   551,   552,
       0,     0,     0,     0,   479,   553,     0,   554,     0,   480,
     481,     0,     0,   482,   483,   555,     0,     0,     0,   556,
     484,   485,     0,   486,   487,     0,   488,     0,   489,     0,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
       0,   491,     0,   492,   493,     0,     0,     0,     0,     0,
       0,     0,     0,   494,     0,   495,     0,     0,     0,     0,
       0,     0,   496,     0,   497,   498,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,   501,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,     0,   509,     0,     0,     0,     0,   510,     0,     0,
       0,     0,     0,     0,   511,     0,     0,   512,     0,     0,
       0,   513,   514,   515,   516,     0,     0,     0,     0,     0,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
     522,   523,   524,   525,   644,     0,   526,     0,     0,   527,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     528,   529,   530,   531,     0,     0,     0,     0,     0,     0,
       0,     0,   645,   532,     0,     0,     0,     0,     0,     0,
       0,     0,   533,     0,   534,     0,     0,     0,     0,     0,
     535,   536,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   537,   538,     0,     0,   539,   540,
       0,     0,     0,     0,     0,     0,     0,   541,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   542,
       0,     0,     0,     0,   543,     0,   544,     0,     0,     0,
       0,     0,     0,     0,   545,     0,     0,   546,   547,   548,
     549,   550,   551,   552,     0,     0,     0,     0,   479,   553,
       0,   554,     0,   480,   481,     0,     0,   482,   483,   555,
       0,     0,     0,   556,   484,   485,     0,   486,   487,     0,
     488,     0,   489,     0,     0,     0,     0,     0,   490,     0,
       0,     0,     0,     0,     0,   491,     0,   492,   493,     0,
       0,     0,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,     0,     0,   496,     0,   497,   498,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     499,   500,   501,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,     0,   509,     0,     0,     0,
       0,   510,     0,     0,     0,     0,     0,     0,   511,     0,
       0,   512,     0,     0,     0,   513,   514,   515,   516,     0,
       0,     0,     0,     0,     0,   517,     0,     0,     0,     0,
     518,     0,     0,     0,   519,     0,     0,   520,     0,     0,
     521,     0,     0,     0,   522,   523,   524,   525,     0,     0,
     526,     0,     0,   527,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   528,   529,   530,   531,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   532,     0,     0,
       0,     0,     0,     0,     0,     0,   533,     0,   534,     0,
       0,     0,     0,     0,   535,   536,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   537,   538,
       0,     0,   539,   540,     0,     0,     0,     0,     0,     0,
       0,   541,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   542,     0,     0,     0,   574,   543,     0,
     544,     0,     0,     0,     0,     0,     0,     0,   545,     0,
       0,   546,   547,   548,   549,   550,   551,   552,     0,     0,
       0,     0,   479,   553,     0,   554,     0,   480,   481,     0,
       0,   482,   483,   555,     0,     0,     0,   556,   484,   485,
       0,   486,   487,     0,   488,     0,   489,     0,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,     0,   491,
       0,   492,   493,     0,     0,     0,     0,     0,     0,     0,
       0,   494,     0,   495,     0,     0,     0,     0,     0,     0,
     496,     0,   497,   498,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   499,   500,   501,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,     0,
     509,     0,     0,     0,     0,   510,     0,     0,     0,     0,
       0,     0,   511,     0,     0,   512,     0,     0,     0,   513,
     514,   515,   516,     0,     0,     0,     0,     0,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,   522,   523,
     524,   525,     0,     0,   526,     0,     0,   527,     0,     0,
       0,     0,   893,     0,     0,     0,     0,     0,   528,   529,
     530,   531,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   532,     0,     0,     0,     0,     0,     0,     0,     0,
     533,     0,   534,     0,     0,     0,     0,     0,   535,   536,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   537,   538,     0,     0,   539,   540,     0,     0,
       0,     0,     0,     0,     0,   541,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   542,     0,     0,
       0,     0,   543,     0,   544,     0,     0,     0,     0,     0,
       0,     0,   545,     0,     0,   546,   547,   548,   549,   550,
     551,   552,     0,     0,     0,     0,   479,   553,     0,   554,
       0,   480,   481,     0,     0,   482,   483,   555,     0,     0,
       0,   556,   484,   485,     0,   486,   487,     0,   488,     0,
     489,     0,     0,     0,     0,     0,   490,     0,     0,     0,
       0,  2484,     0,   491,     0,   492,   493,     0,     0,     0,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,     0,     0,     0,   496,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   499,   500,
     501,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,     0,   509,     0,     0,     0,     0,   510,
       0,     0,     0,     0,     0,     0,   511,     0,     0,   512,
       0,     0,     0,   513,   514,   515,   516,     0,     0,     0,
       0,     0,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,   522,   523,   524,   525,     0,     0,   526,     0,
       0,   527,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   528,   529,   530,   531,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   532,     0,     0,     0,     0,
       0,     0,     0,     0,   533,     0,   534,     0,     0,     0,
       0,     0,   535,   536,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   537,   538,     0,     0,
     539,   540,     0,     0,     0,     0,     0,     0,     0,   541,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   542,     0,     0,     0,     0,   543,     0,   544,     0,
       0,     0,     0,     0,     0,     0,   545,     0,     0,   546,
     547,   548,   549,   550,   551,   552,     0,     0,     0,     0,
     479,   553,     0,   554,     0,   480,   481,     0,     0,   482,
     483,   555,     0,     0,     0,   556,   484,   485,     0,   486,
     487,     0,   488,     0,   489,     0,     0,     0,     0,     0,
     490,     0,     0,     0,     0,  2787,     0,   491,     0,   492,
     493,     0,     0,     0,     0,     0,     0,     0,     0,   494,
       0,   495,     0,     0,     0,     0,     0,     0,   496,     0,
     497,   498,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   499,   500,   501,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,     0,   509,     0,
       0,     0,     0,   510,     0,     0,     0,     0,     0,     0,
     511,     0,     0,   512,     0,     0,     0,   513,   514,   515,
     516,     0,     0,     0,     0,     0,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,     0,     0,     0,   522,   523,   524,   525,
       0,     0,   526,     0,     0,   527,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   528,   529,   530,   531,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   532,
       0,     0,     0,     0,     0,     0,     0,     0,   533,     0,
     534,     0,     0,     0,     0,     0,   535,   536,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     537,   538,     0,     0,   539,   540,     0,     0,     0,     0,
       0,     0,     0,   541,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   542,     0,     0,     0,     0,
     543,     0,   544,     0,     0,     0,     0,     0,     0,     0,
     545,     0,     0,   546,   547,   548,   549,   550,   551,   552,
       0,     0,     0,     0,   479,   553,     0,   554,     0,   480,
     481,     0,     0,   482,   483,   555,     0,     0,     0,   556,
     484,   485,     0,   486,   487,     0,   488,     0,   489,     0,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
       0,   491,     0,   492,   493,     0,     0,     0,     0,     0,
       0,     0,     0,   494,     0,   495,     0,     0,     0,     0,
       0,     0,   496,     0,   497,   498,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,   501,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,     0,   509,     0,     0,     0,     0,   510,     0,     0,
       0,     0,     0,     0,   511,     0,     0,   512,     0,     0,
       0,   513,   514,   515,   516,     0,     0,     0,     0,     0,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
     522,   523,   524,   525,     0,     0,   526,     0,     0,   527,
       0,     0,     0,     0,  2811,     0,     0,     0,     0,     0,
     528,   529,   530,   531,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   532,     0,     0,     0,     0,     0,     0,
       0,     0,   533,     0,   534,     0,     0,     0,     0,     0,
     535,   536,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   537,   538,     0,     0,   539,   540,
       0,     0,     0,     0,     0,     0,     0,   541,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   542,
       0,     0,     0,     0,   543,     0,   544,     0,     0,     0,
       0,     0,     0,     0,   545,     0,     0,   546,   547,   548,
     549,   550,   551,   552,     0,     0,     0,     0,   479,   553,
       0,   554,     0,   480,   481,     0,     0,   482,   483,   555,
       0,     0,     0,   556,   484,   485,     0,   486,   487,     0,
     488,     0,   489,     0,     0,     0,     0,     0,   490,     0,
       0,     0,     0,  3167,     0,   491,     0,   492,   493,     0,
       0,     0,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,     0,     0,   496,     0,   497,   498,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     499,   500,   501,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,     0,   509,     0,     0,     0,
       0,   510,     0,     0,     0,     0,     0,     0,   511,     0,
       0,   512,     0,     0,     0,   513,   514,   515,   516,     0,
       0,     0,     0,     0,     0,   517,     0,     0,     0,     0,
     518,     0,     0,     0,   519,     0,     0,   520,     0,     0,
     521,     0,     0,     0,   522,   523,   524,   525,     0,     0,
     526,     0,     0,   527,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   528,   529,   530,   531,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   532,     0,     0,
       0,     0,     0,     0,     0,     0,   533,     0,   534,     0,
       0,     0,     0,     0,   535,   536,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   537,   538,
       0,     0,   539,   540,     0,     0,     0,     0,     0,     0,
       0,   541,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,   542,     0,     0,     0,     0,   543,     0,
     544,     0,     0,     0,     0,     0,     0,     0,   545,     0,
       0,   546,   547,   548,   549,   550,   551,   552,     0,     0,
       0,     0,   479,   553,     0,   554,     0,   480,   481,     0,
       0,   482,   483,   555,     0,     0,     0,   556,   484,   485,
       0,   486,   487,     0,   488,     0,   489,     0,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,     0,   491,
       0,   492,   493,     0,     0,     0,     0,     0,     0,     0,
       0,   494,     0,   495,     0,     0,     0,     0,     0,     0,
     496,     0,   497,   498,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   499,   500,   501,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,     0,
     509,     0,     0,     0,     0,   510,     0,     0,     0,     0,
       0,     0,   511,     0,     0,   512,     0,     0,     0,   513,
     514,   515,   516,     0,     0,     0,     0,     0,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,   522,   523,
     524,   525,     0,     0,   526,     0,     0,   527,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   528,   529,
     530,   531,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   532,     0,     0,     0,     0,     0,     0,     0,     0,
     533,     0,   534,     0,     0,     0,     0,     0,   535,   536,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   537,   538,     0,     0,   539,   540,     0,     0,
       0,     0,     0,     0,     0,   541,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   542,     0,     0,
       0,  3517,   543,     0,   544,     0,     0,     0,     0,     0,
       0,     0,   545,     0,     0,   546,   547,   548,   549,   550,
     551,   552,     0,     0,     0,     0,   479,   553,     0,   554,
       0,   480,   481,     0,     0,   482,   483,   555,     0,     0,
       0,   556,   484,   485,     0,   486,   487,     0,   488,     0,
     489,     0,     0,     0,     0,     0,   490,     0,     0,     0,
       0,     0,     0,   491,     0,   492,   493,     0,     0,     0,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,     0,     0,     0,   496,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   499,   500,
     501,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,     0,   509,     0,     0,     0,     0,   510,
       0,     0,     0,     0,     0,     0,   511,     0,     0,   512,
       0,     0,     0,   513,   514,   515,   516,     0,     0,     0,
       0,     0,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,   522,   523,   524,   525,     0,     0,   526,     0,
       0,   527,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   528,   529,   530,   531,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   532,     0,     0,     0,     0,
       0,     0,     0,     0,   533,     0,   534,     0,     0,     0,
       0,     0,   535,   536,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   537,   538,     0,     0,
     539,   540,     0,     0,     0,     0,     0,     0,     0,   541,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   542,     0,     0,     0,     0,   543,     0,   544,     0,
       0,     0,     0,     0,     0,     0,   545,     0,     0,   546,
     547,   548,   549,   550,   551,   552,     0,     0,     0,     0,
     479,   553,     0,   554,     0,   480,   481,     0,     0,   482,
     483,   555,     0,     0,     0,   556,   484,   485,     0,   486,
     487,     0,   488,     0,   489,     0,     0,     0,     0,     0,
     490,     0,     0,     0,     0,     0,     0,   491,     0,   492,
     493,     0,     0,     0,     0,     0,     0,     0,     0,   494,
       0,   495,     0,     0,     0,     0,     0,     0,   496,     0,
     497,   498,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   499,   500,   501,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,     0,   509,     0,
       0,     0,     0,   510,     0,     0,     0,     0,     0,     0,
     511,     0,     0,     0,     0,     0,     0,   513,   514,   515,
     516,     0,     0,     0,     0,     0,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,     0,     0,     0,   522,   523,   524,   525,
       0,     0,   526,     0,     0,   527,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   528,   529,   530,   531,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   532,
       0,     0,     0,     0,     0,     0,     0,     0,   533,     0,
     534,     0,     0,     0,     0,     0,   535,   536,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     537,   538,   479,     0,   539,   540,     0,   480,   481,     0,
       0,   482,   483,   541,     0,     0,     0,     0,     0,   899,
       0,   486,   487,     0,   488,   542,   489,     0,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,     0,   491,
     545,   492,   493,   546,   547,   548,   549,   550,   551,   552,
       0,   494,     0,   495,     0,   553,     0,   554,     0,     0,
       0,     0,   497,   498,     0,   555,     0,     0,     0,   556,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   499,   500,     0,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,     0,
    1520,     0,     0,     0,     0,   510,     0,     0,     0,     0,
       0,     0,   511,     0,     0,     0,     0,     0,     0,   513,
     514,   515,   516,     0,     0,     0,     0,     0,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,     0,   523,
     524,     0,     0,     0,   526,     0,     0,   527,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   528,   529,
     530,   531,     0,     0,     0,     0,     0,     0,     0,     0,
       0,   532,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   534,     0,     0,     0,     0,     0,     0,   536,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   537,   538,   479,     0,     0,     0,     0,   480,
     481,     0,     0,   482,   483,     0,     0,     0,  1521,  1522,
       0,   899,     0,   486,   487,     0,   488,  1523,   489,     0,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
       0,   491,     0,   492,   493,  1524,  1525,   548,  1526,  1527,
     551,   552,     0,   494,     0,   495,     0,   553,     0,   554,
       0,     0,     0,     0,   497,   498,     0,   555,     0,     0,
       0,   556,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,     0,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,     0,     0,     0,     0,     0,     0,   510,     0,     0,
       0,     0,     0,     0,   511,     0,     0,     0,     0,     0,
       0,   513,   514,   515,   516,     0,     0,     0,     0,     0,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
       0,   523,   524,     0,     0,     0,   526,     0,   479,   527,
       0,     0,     0,   480,   481,     0,     0,   482,   483,     0,
     528,   529,   530,   531,     0,   899,     0,   486,   487,     0,
     488,     0,   489,   532,     0,     0,     0,     0,   490,     0,
       0,     0,     0,     0,   534,   491,     0,   492,   493,     0,
       0,   536,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,   537,   538,     0,     0,   497,   498,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     499,   500,     0,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,     0,     0,     0,  1601,  1602,
       0,   510,   551,   552,     0,     0,     0,     0,   511,     0,
       0,     0,     0,     0,     0,   513,   514,   515,   516,   555,
       0,     0,     0,   556,     0,   517,     0,     0,     0,  1352,
     518,     0,     0,     0,   519,     0,     0,   520,     0,     0,
     521,     0,     0,     0,     0,   523,   524,     0,     0,     0,
     526,     0,   479,   527,     0,     0,     0,   480,   481,     0,
       0,   482,   483,     0,   528,   529,   530,   531,     0,   899,
       0,   486,   487,     0,   488,     0,   489,   532,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,   534,   491,
       0,   492,   493,     0,     0,   536,     0,     0,     0,     0,
       0,   494,     0,   495,     0,     0,     0,     0,   537,   538,
       0,     0,   497,   498,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  1558,   499,   500,     0,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,     0,
       0,     0,     0,     0,     0,   510,   551,   552,     0,     0,
       0,     0,   511,     0,     0,     0,     0,     0,     0,   513,
     514,   515,   516,   555,     0,     0,     0,   556,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,     0,   523,
     524,     0,     0,     0,   526,     0,   479,   527,     0,     0,
       0,   480,   481,     0,     0,   482,   483,     0,   528,   529,
     530,   531,     0,   899,     0,   486,   487,     0,   488,     0,
     489,   532,     0,     0,     0,     0,   490,     0,     0,     0,
       0,     0,   534,   491,     0,   492,   493,     0,     0,   536,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,     0,   537,   538,     0,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   499,   500,
       0,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,     0,     0,     0,     0,     0,  1398,   510,
     551,   552,     0,     0,     0,     0,   511,     0,     0,     0,
       0,     0,     0,   513,   514,   515,   516,   555,     0,     0,
       0,   556,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,     0,   523,   524,     0,     0,     0,   526,     0,
     479,   527,     0,     0,     0,   480,   481,     0,     0,   482,
     483,     0,   528,   529,   530,   531,     0,   899,     0,   486,
     487,     0,   488,     0,   489,   532,  1679,     0,     0,     0,
     490,     0,     0,     0,     0,     0,   534,   491,     0,   492,
     493,     0,     0,   536,     0,     0,     0,     0,     0,   494,
       0,   495,     0,     0,     0,     0,   537,   538,     0,     0,
     497,   498,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,   499,   500,     0,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,     0,     0,     0,
    1783,     0,     0,   510,   551,   552,     0,     0,     0,     0,
     511,     0,     0,     0,     0,     0,     0,   513,   514,   515,
     516,   555,     0,     0,     0,   556,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,     0,     0,     0,     0,   523,   524,     0,
       0,     0,   526,     0,   479,   527,     0,     0,     0,   480,
     481,     0,     0,   482,   483,     0,   528,   529,   530,   531,
       0,   899,     0,   486,   487,     0,   488,     0,   489,   532,
       0,     0,     0,     0,   490,     0,     0,     0,     0,     0,
     534,   491,     0,   492,   493,     0,     0,   536,     0,     0,
       0,     0,     0,   494,     0,   495,     0,     0,     0,     0,
     537,   538,     0,     0,   497,   498,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   499,   500,     0,   502,
       0,   503,     0,   504,     0,   505,   506,   507,     0,   508,
       0,     0,     0,     0,     0,     0,     0,   510,   551,   552,
       0,     0,     0,     0,   511,     0,     0,     0,     0,     0,
       0,   513,   514,   515,   516,   555,     0,     0,     0,   556,
       0,   517,     0,     0,     0,     0,   518,     0,     0,     0,
     519,     0,     0,   520,     0,     0,   521,     0,     0,     0,
       0,   523,   524,     0,     0,     0,   526,     0,   479,   527,
       0,     0,     0,   480,   481,     0,     0,   482,   483,     0,
     528,   529,   530,   531,     0,   899,     0,   486,   487,     0,
     488,     0,   489,   532,     0,     0,     0,     0,   490,     0,
       0,     0,     0,     0,   534,   491,     0,   492,   493,     0,
       0,   536,     0,     0,     0,     0,     0,   494,     0,   495,
       0,     0,     0,     0,   537,   538,     0,     0,   497,   498,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,  2270,
     499,   500,     0,   502,     0,   503,     0,   504,     0,   505,
     506,   507,     0,   508,     0,     0,     0,     0,     0,     0,
       0,   510,   551,   552,     0,     0,     0,     0,   511,     0,
       0,     0,     0,     0,     0,   513,   514,   515,   516,   555,
       0,     0,     0,   556,     0,   517,     0,     0,     0,     0,
     518,     0,     0,     0,   519,     0,     0,   520,     0,     0,
     521,     0,     0,     0,     0,   523,   524,     0,     0,     0,
     526,     0,   479,   527,     0,     0,     0,   480,   481,     0,
       0,   482,   483,     0,   528,   529,   530,   531,     0,   899,
       0,   486,   487,     0,   488,     0,   489,   532,     0,     0,
       0,     0,   490,     0,     0,     0,     0,     0,   534,   491,
       0,   492,   493,     0,     0,   536,     0,     0,     0,     0,
       0,   494,     0,   495,     0,     0,     0,     0,   537,   538,
       0,     0,   497,   498,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,  3458,   499,   500,     0,   502,     0,   503,
       0,   504,     0,   505,   506,   507,     0,   508,     0,     0,
       0,     0,     0,     0,     0,   510,   551,   552,     0,     0,
       0,     0,   511,     0,     0,     0,     0,     0,     0,   513,
     514,   515,   516,   555,     0,     0,     0,   556,     0,   517,
       0,     0,     0,     0,   518,     0,     0,     0,   519,     0,
       0,   520,     0,     0,   521,     0,     0,     0,     0,   523,
     524,     0,     0,     0,   526,     0,   479,   527,     0,     0,
       0,   480,   481,     0,     0,   482,   483,     0,   528,   529,
     530,   531,     0,   899,     0,   486,   487,     0,   488,     0,
     489,   532,     0,     0,     0,     0,   490,     0,     0,     0,
       0,     0,   534,   491,     0,   492,   493,     0,     0,   536,
       0,     0,     0,     0,     0,   494,     0,   495,     0,     0,
       0,     0,   537,   538,     0,     0,   497,   498,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,  3519,   499,   500,
       0,   502,     0,   503,     0,   504,     0,   505,   506,   507,
       0,   508,     0,     0,     0,     0,     0,     0,     0,   510,
     551,   552,     0,     0,     0,     0,   511,     0,     0,     0,
       0,     0,     0,   513,   514,   515,   516,   555,     0,     0,
       0,   556,     0,   517,     0,     0,     0,     0,   518,     0,
       0,     0,   519,     0,     0,   520,     0,     0,   521,     0,
       0,     0,     0,   523,   524,     0,     0,     0,   526,     0,
     479,   527,     0,     0,     0,   480,   481,     0,     0,   482,
     483,     0,   528,   529,   530,   531,     0,   899,     0,   486,
     487,     0,   488,     0,   489,   532,     0,     0,     0,     0,
     490,     0,     0,     0,     0,     0,   534,   491,     0,   492,
     493,     0,     0,   536,     0,     0,     0,     0,     0,   494,
       0,   495,     0,     0,     0,     0,   537,   538,     0,     0,
     497,   498,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,  3658,   499,   500,     0,   502,     0,   503,     0,   504,
       0,   505,   506,   507,     0,   508,     0,     0,     0,     0,
       0,     0,     0,   510,   551,   552,     0,     0,     0,     0,
     511,     0,     0,     0,     0,     0,     0,   513,   514,   515,
     516,   555,     0,   689,     0,   556,     0,   517,     0,     0,
       0,     0,   518,     0,     0,     0,   519,     0,     0,   520,
       0,     0,   521,   144,   690,     0,     0,   523,   524,     0,
     691,     0,   526,     0,     0,   527,   149,   150,   151,     0,
       0,     0,     0,     0,   153,     0,   528,   529,   530,   531,
       0,     0,   155,     0,     0,     0,     0,     0,     0,   532,
       0,     0,     0,   692,     0,     0,     0,     0,     0,   159,
     534,     0,     0,     0,     0,     0,   160,   536,     0,     0,
       0,     0,     0,     0,   689,     0,     0,     0,     0,     0,
     537,   538,   161,   162,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,   144,   690,     0,     0,     0,     0,
       0,   691,     0,     0,     0,     0,     0,   149,   150,   151,
       0,     0,     0,     0,     0,   153,   165,   166,     0,   693,
       0,   168,   169,   155,     0,   170,     0,     0,   551,   552,
       0,     0,     0,     0,   692,     0,     0,     0,     0,     0,
     159,     0,     0,     0,   172,   555,     0,   160,     0,   556,
       0,     0,     0,     0,   173,     0,     0,     0,     0,     0,
       0,     0,     0,   161,   162,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,   174,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,   175,
     176,     0,     0,     0,     0,   177,     0,   165,   166,     0,
     693,     0,   168,   169,   178,     0,   170,     0,     0,     0,
     179,   180,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,   172,   181,     0,     0,     0,
       0,     0,     0,     0,     0,   173,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,   694,     0,  2560,     0,
     182,     0,     0,     0,     0,     0,     0,     0,  2561,   174,
       0,     0,  2562,     0,     0,  2563,     0,     0,     0,  2564,
     175,   176,   188,     0,  2565,     0,   177,     0,     0,     0,
    2566,     0,   150,     0,     0,   178,     0,     0,     0,     0,
       0,   179,   180,     0,     0,     0,     0,   155,     0,  2853,
       0,     0,  2567,     0,     0,  2568,     0,   181,  2569,     0,
       0,     0,     0,  2570,     0,     0,     0,  2571,     0,     0,
       0,   160,     0,     0,     0,     0,     0,   698,     0,     0,
       0,   182,     0,     0,     0,     0,  2572,   161,   162,     0,
       0,  2560,     0,     0,  2573,     0,     0,     0,     0,  2574,
       0,  2561,     0,   188,     0,  2562,     0,     0,  2563,     0,
       0,     0,  2564,     0,     0,     0,     0,  2565,     0,     0,
       0,  2575,     0,  2566,  2576,   150,   168,  1352,     0,     0,
    2577,     0,     0,     0,     0,     0,  2560,     0,     0,  3058,
     155,     0,     0,     0,     0,  2567,  2561,     0,  2568,   172,
    2562,  2569,     0,  2563,     0,     0,  2570,  2564,  2578,  1557,
    2571,     0,  2565,     0,   160,     0,     0,     0,  2566,     0,
     150,     0,     0,     0,     0,     0,     0,     0,     0,  2572,
     161,   162,  2579,     0,     0,   155,     0,  2573,     0,     0,
    2567,     0,  2574,  2568,     0,     0,  2569,     0,     0,     0,
       0,  2570,     0,     0,     0,  2571,     0,     0,     0,   160,
       0,     0,     0,     0,  2575,     0,     0,  2576,     0,   168,
    1352,     0,     0,  2577,  2572,   161,   162,     0,     0,     0,
       0,  1558,  2573,     0,     0,     0,     0,  2574,     0,     0,
       0,     0,   172,  2580,     0,     0,     0,     0,     0,     0,
       0,  2578,  1557,     0,   551,   552,     0,     0,     0,  2575,
       0,     0,  2576,     0,   168,  1352,     0,     0,  2577,     0,
       0,     0,     0,     0,     0,  2579,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   172,     0,     0,
       2,     0,     0,     3,     4,     5,  2578,  1557,     0,     6,
       7,     8,     9,     0,     0,    10,    11,    12,     0,    13,
      14,     0,    15,    16,     0,    17,    18,    19,    20,    21,
    2579,     0,     0,     0,  1558,     0,    23,     0,     0,     0,
       0,     0,     0,     0,     0,     0,  2580,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,   551,   552,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,     0,     0,     0,  1558,
       0,     3,     4,     5,     0,     0,     0,     6,     7,     0,
       9,  2580,     0,    10,    11,     0,     0,    13,    14,     0,
       0,    16,   551,   552,    18,    19,    20,    21,     0,  1191,
       0,     0,     0,     0,    23,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    24,    25,    26,
      27,    28,    29,    30,    31,    32,    33,    34,    35,    36,
      37,    38,    39,    40,     3,     4,     5,     0,     0,     0,
       6,     7,     0,     9,     0,     0,    10,    11,     0,     0,
      13,    14,     0,     0,    16,     0,     0,    18,    19,    20,
      21,     0,     0,     0,     0,     0,     0,    23,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
      24,    25,    26,    27,    28,    29,    30,    31,    32,    33,
      34,    35,    36,    37,    38,    39,    40
};

static const yytype_int16 yycheck[] =
{
     149,  1485,   151,   167,   970,  1068,   353,   920,  1106,  1115,
     350,  1486,  1487,  1803,   927,   362,  1854,  1729,   174,   606,
    1829,   917,   729,   910,   911,  1978,  1387,  1865,  1118,  2084,
     126,  1240,   724,  1054,   160,   161,   162,  1060,  1600,  1853,
    2501,   127,  1855,   169,   121,    52,   172,  1066,   334,   619,
     165,  1363,   905,  1365,    51,  2672,  1730,   734,  2090,  1231,
      57,  2093,  2060,  1737,  2577,  1322,    65,  2836,   872,  2101,
    2295,  1319,  2650,  2651,  2652,   347,   374,  2131,   965,  2902,
      52,  2578,  1328,  1354,  2596,  1753,  1018,  2927,  1334,   931,
    2561,  2149,  2304,  2169,  2239,  2309,  2893,   104,  2504,  1899,
       0,  2572,  2257,  2258,   260,  1351,  1121,  2457,  2449,  3039,
    1324,  2165,  3117,  2591,  2164,  1332,  2810,   854,   342,  2881,
    2882,  2883,   119,   362,  3054,  2350,    39,    39,    39,    60,
     814,  3070,  2254,    39,   817,   111,   102,  2362,    39,   295,
     296,   297,   114,   115,    39,    60,  3282,   107,   420,   130,
     115,   109,   125,    53,  1812,   117,  1558,   313,    58,    59,
     114,  1563,   115,    63,   103,    39,   141,    63,    61,    62,
     137,   174,   110,  1015,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,   100,   199,  1972,   164,   169,   199,
     134,   208,   111,  1993,   164,   103,   106,  3050,   106,   189,
     179,    39,   140,   125,   104,   208,   130,   235,    96,   220,
     110,  2724,   181,   117,   110,   246,   157,   124,   185,   152,
     268,   121,   122,   108,   233,   121,   122,   177,   221,   145,
     160,  1848,   218,   160,   103,   142,   158,  2287,  2919,   312,
     165,   205,   216,   236,   151,   152,   310,   163,  1354,   156,
     157,   347,   151,   103,   198,   109,   265,   110,   308,   309,
     159,   309,    52,    53,    54,   337,   402,   166,    85,   168,
    3110,   170,   247,   345,   173,   174,   236,   433,   434,   435,
      97,   437,   438,   419,   440,   441,  2747,   140,   361,   265,
     142,  1562,  2342,   257,   144,   239,   289,   361,  2810,   151,
    3230,   365,   375,   277,   460,   461,   462,   463,   230,  2385,
     179,   361,   197,   361,  2811,  2827,   249,   394,   248,   288,
     236,   248,   226,   239,   420,   235,   180,  1390,   337,   237,
     361,   219,   239,   361,   103,   484,   333,   106,   137,   258,
     357,  2395,   103,   340,   137,   128,   256,  2561,   644,   645,
     361,   361,   111,   343,   357,   114,  2156,  2479,  2572,  2514,
    2766,   260,   379,  2577,   314,   337,   345,   160,   361,  2419,
     337,   343,   123,   343,   360,   361,   379,   128,   392,   344,
     361,   343,  2596,  2437,   361,   361,   361,  2509,   361,   130,
     362,   356,   373,   152,   360,   361,   295,   296,   297,   337,
     358,   361,   360,   361,   314,   752,   413,   361,   361,   756,
     750,   758,   759,   760,   313,   762,   413,   361,   317,  1903,
    3556,   360,   361,   141,   378,   772,   582,   583,   169,   585,
     586,   587,   588,   589,   590,   376,   592,   361,   594,   361,
     340,   135,   350,   351,   368,   361,   602,  3025,   734,  2262,
    3131,   361,  3038,  3383,   361,   248,   378,   361,  3397,  2272,
     211,  1374,  1375,  3232,  1483,  1149,  1485,  1150,   237,   741,
     810,  1358,  1042,  1043,  1044,  1045,  1046,  1047,  1048,  1049,
    1050,  1051,  1052,  1053,   415,   771,   397,  3492,  3493,   787,
     788,   789,   398,   404,   394,  2153,   397,  1899,   394,   785,
     133,   416,   397,   404,  1391,   416,   358,   420,   420,  3306,
    2724,   667,   668,   413,   670,   739,  1429,   756,   411,   412,
     806,  1258,   746,   397,   141,   399,   690,  2313,  3381,   693,
    1417,  3225,   293,   432,   433,   434,   435,  3050,   437,   438,
     439,   440,   441,   815,   443,   444,  3476,  1764,   347,   417,
     130,  3048,  1809,   119,   453,   338,   166,  3035,  2358,   397,
     343,   460,   461,   462,   463,    96,   404,   261,   361,   468,
     469,  3042,  1685,   472,  2915,  2800,  3047,  2194,  2195,  2196,
     418,   350,  2932,  2200,   106,  3056,   337,   138,   127,   348,
    2996,  3431,   174,  1807,  3417,  3418,  2810,  2647,   155,  1614,
    3458,  2746,  2555,  3428,  2759,  2760,   236,   397,  2990,   399,
    1523,   401,   147,  2827,  2567,  3545,   249,   542,  2418,  3416,
     361,  3684,   205,   123,  1737,   128,   385,  3632,  3633,   227,
    2706,  2707,   373,  3219,   393,   394,   535,  2695,   179,  3152,
    1482,  3704,   360,   361,    25,   741,   135,    80,   204,  2704,
     127,  3491,   137,  2606,  2708,  2493,  2868,    38,    39,  1591,
      41,  1932,  3248,  3249,   215,  1936,   202,   361,   204,   137,
    2668,    52,    53,   750,   205,   121,  2901,   208,   236,   578,
     119,   580,   581,   582,   583,   251,   585,   586,   587,   588,
     589,   590,   591,   592,   593,   594,   218,   596,   597,   204,
     185,   857,   191,   602,   121,    80,   202,   606,   204,   865,
    3222,   211,   202,  3225,   204,   126,   257,   873,   643,   815,
    3578,  2389,  3234,   281,   290,   282,   882,   360,   361,   280,
     886,   361,   298,   810,   256,   345,  2550,  3499,  3563,  3236,
    3237,  1950,  2542,   360,   361,  1332,  1042,  1043,  1044,  1045,
    1046,  1047,  1048,  1049,  1050,  1051,  1052,  1053,   297,   766,
     343,  2575,   661,   345,  3235,   233,   211,   127,   667,   668,
     669,   670,   671,   672,  3597,  3598,   204,  3546,   893,   377,
     257,   361,   897,   204,   756,   934,  1590,  3464,   368,   945,
     236,   226,   314,  1140,   360,   361,  1136,   265,  3560,  3561,
     956,  3387,  3388,   361,  3186,   361,   202,   814,   204,   360,
     361,  3636,   251,   928,   314,   201,   166,   814,   817,   236,
     356,  3590,   357,   374,   202,   314,   204,  3575,  3042,  1935,
     381,   382,   367,  3047,   369,   338,  3050,   149,   150,  1902,
     343,   231,  3056,  1430,  2205,  3670,  1416,  3425,   384,  2649,
     178,   290,   337,  1151,   204,  1011,   361,  2066,   141,   298,
    1016,  1017,  1134,   302,   127,   361,   766,   204,  3381,   337,
    1562,   361,  1893,  2045,  3386,  2930,   104,   105,   239,   239,
    1029,  3658,  1031,  2937,  1974,   168,   114,  1036,  1037,  1038,
    1039,  1040,  1041,   181,  3642,  2141,   181,  2209,  2210,  1055,
     345,  2899,  2150,  1924,  2161,  3682,  2154,   293,  3585,   246,
     202,  1060,   204,  2225,  2226,  2947,   116,   145,  1190,  3497,
    3498,   360,   361,   251,   152,   242,   361,   233,    25,   239,
     149,   123,   220,   361,   217,   220,   347,   297,  3152,  1852,
     361,    38,    39,   354,    41,  1622,  1102,   242,  3565,   360,
     361,   268,  3700,  3701,   350,    52,    53,   285,   857,   246,
    1109,  1857,  1858,   374,   247,   864,   865,   250,   893,   868,
     869,   361,   897,   242,   873,   361,   200,   149,   356,   878,
    1876,  1877,  1835,   882,   192,    25,   885,   886,  2802,   211,
     314,   303,   249,   343,   257,   920,   361,   233,    38,    39,
     361,    41,   927,   928,   903,   904,   343,   101,  3222,   420,
     338,  3225,    52,    53,   166,   178,   397,   382,  3635,   113,
    3234,  3235,   403,   404,   405,   406,   407,   408,   263,   265,
     929,   337,   931,   233,   291,   934,   935,   361,  1134,   420,
     939,   940,   179,   262,   361,  2719,   945,   267,  2523,  3666,
     242,   361,   177,   123,   233,   177,   343,   956,   128,  1136,
     134,   289,   350,   215,   356,   350,   361,   384,   142,   361,
     278,   970,  3297,   361,   192,  3692,   361,   151,   361,   103,
     308,   309,   106,   242,   175,   240,   211,  3142,   251,   211,
     262,   249,   361,    25,  1190,   220,   233,   188,   220,  1024,
    1025,   337,  2208,  1189,   328,   329,    38,    39,   343,    41,
     332,  3064,  1011,  1012,  1013,   337,  1015,  1016,  1017,  1223,
      52,    53,   285,   345,   198,   361,   103,    97,   265,   106,
       0,   355,   356,   291,   358,   359,  1133,     7,  2157,  2952,
    2953,   211,  1149,  1042,  1043,  1044,  1045,  1046,  1047,  1048,
    1049,  1050,  1051,  1052,  1053,  1054,  1055,  1313,   337,   138,
    2179,  1060,  2268,  2976,   384,   239,  1065,  3381,  2191,  1068,
    1069,  1070,  3386,  1072,  1073,   338,   246,  1764,   293,    96,
     276,    51,   307,    53,  2282,   307,   273,    57,   279,   314,
    1339,    61,   314,  1342,  3655,    65,   141,  3422,   177,  3424,
     337,   103,   361,  1102,   106,    96,   270,  1311,   274,   364,
     362,    81,   337,   237,  1113,  2236,    96,  1116,   336,   337,
     103,   339,   374,   106,   402,   380,  1352,   345,   357,   381,
     382,   220,  2253,     0,  2946,   387,   391,   103,    97,   138,
     106,   419,  1357,   395,  1936,   344,   361,   231,  3062,   119,
     379,   121,  3307,   137,   124,  3069,   137,   356,   142,   265,
     237,   142,   132,  3216,   360,   361,   255,   151,   178,   356,
     151,   255,   217,   337,  3083,   120,   255,   258,   177,   189,
     271,  1628,  1629,   177,  1631,    25,    53,   361,   205,   234,
     356,   208,   138,  1633,  1634,  1635,   241,   242,    38,    39,
     397,    41,   247,    96,  1203,   138,   403,   404,   405,   406,
     407,   408,    52,    53,   205,   275,   261,   208,  1888,   279,
     165,   181,   419,   420,  2211,   205,   361,   218,   208,    39,
     741,   177,   277,   314,   141,   237,  1622,   343,   218,   284,
    2227,   251,   271,    96,   177,   190,   337,   267,   145,  1498,
    1499,   296,  1638,   388,   237,  1254,   255,   397,   398,   243,
     220,   255,   243,   403,   404,   405,   406,   407,   408,   214,
      97,   237,  2259,  2734,   304,   285,   787,   788,   789,   790,
     791,   792,   793,   794,   795,   796,   797,   798,   799,   800,
     801,   802,   803,   804,   805,  2957,   356,   281,    96,   283,
     281,   361,   199,   200,   815,  1749,   275,   252,   337,   255,
     217,  1310,   205,   343,  1313,   208,   361,   310,    96,  1318,
    1319,   276,   255,  2735,  2736,   218,  2532,   234,  2740,  2741,
     200,  3384,  1357,  1332,  2643,   242,  1335,   420,   120,   236,
     247,   361,   242,   175,   162,  2757,  2758,  1346,   180,  1374,
    1375,  1600,   205,   211,   261,   208,   188,   357,    89,   174,
    1616,   361,   287,   333,   384,   397,  1810,   199,   361,   187,
     340,   403,   404,   405,   406,   407,   408,   284,   292,   108,
     350,  2500,   352,   112,   217,   114,   418,   356,   246,   296,
     304,  1390,   361,   208,   402,   192,  1395,   345,  3575,  2518,
     348,   234,   131,    63,  1429,   360,   361,   205,   190,   242,
     208,   419,  1411,   210,   247,  1414,   136,   199,   200,   319,
     320,  3474,   314,   152,   394,  3000,  3001,   205,   275,   343,
     208,  1430,   214,  3610,  3611,   360,   361,   337,   268,    25,
    2630,   223,   374,   413,  1640,    89,   338,   279,   418,   381,
     110,   284,    38,    39,   361,    41,   286,  2470,   328,   329,
     360,   361,   122,   296,  1720,  3642,    52,    53,   197,   361,
     252,   339,   342,   142,   344,   178,  1475,   345,    25,   309,
    2476,  2477,   151,  1482,   259,   355,   356,     0,   358,   359,
    3399,    38,    39,   222,    41,  2491,  2492,   231,  1523,  3676,
    2307,   512,  3314,   335,   207,    52,    53,  3684,   242,   356,
     136,  3449,  1761,  1762,   361,  2511,  2512,   349,   350,   351,
    3697,  3698,  3699,  3700,  3701,  1781,  1782,  3704,   361,   314,
     305,   361,   543,   544,   358,   167,   337,   361,   123,  3592,
      53,   268,   269,   128,   176,    58,    59,  1546,   251,  1548,
    2220,  2221,   184,   338,  2001,  2002,   314,   397,  1557,  1999,
     289,   110,   314,   403,   404,   405,   406,   407,   408,   126,
     398,  3624,   204,  1822,  2693,   167,   361,   337,   418,  1578,
     338,   348,   285,   402,   176,   142,   338,   314,   402,   318,
     182,   140,   184,   167,   151,  2793,   338,   229,  3488,   418,
     360,   361,   176,   361,   418,   190,   336,   337,    25,   361,
     184,  1610,  1611,  1612,  1613,   345,   344,  1616,   360,   361,
     135,    38,    39,  1134,    41,   348,   211,   344,   356,   214,
     204,   360,   361,   402,   211,    52,    53,   229,  1853,   356,
    1151,   358,   142,   220,   361,  2764,   402,   372,  1863,   418,
      25,   151,   402,   168,   402,   229,  1905,   337,   402,  1908,
     105,   386,   418,    38,    39,   345,    41,   252,   418,   342,
     418,   344,   117,  1672,   418,   420,   142,    52,    53,  1190,
    1679,  1680,   142,   356,   342,   151,   344,  1686,  1687,  2808,
     400,   151,  1691,   342,  1693,   344,  2762,  1696,   356,  1698,
    1699,  1700,   217,  1702,  1703,  1704,  1705,   356,  1707,  1708,
      25,  1710,   345,  1962,  1713,   348,  1715,   348,  1717,   234,
     235,  1720,   292,    38,    39,   339,    41,   242,   234,   360,
     361,   345,   247,   336,   304,   417,   242,    52,    53,   357,
     357,   256,   345,  1742,   357,  1960,   261,   360,   361,   367,
     367,   369,   369,   231,   367,   337,   369,   339,   142,    25,
    3172,  3173,   240,   345,   348,  1764,   348,   151,   337,   284,
    3345,  1770,    38,    39,  2761,    41,   345,  1776,   200,   357,
     750,   296,  1781,  1782,   357,  1784,    52,    53,   361,   367,
     205,   369,  1791,   208,   367,   310,   369,   357,   357,   314,
     770,   361,    87,   773,   357,  2924,   196,   367,   367,   369,
     369,   397,  1811,   203,   367,   337,   369,   403,   404,   405,
     406,   407,   408,   345,   356,  3409,   358,  1852,  1853,   361,
    1829,  2046,   418,  1832,  2997,   337,  1233,   339,  1863,  1236,
     810,  3004,   812,   345,   814,   347,   361,   817,   356,   357,
     397,   360,   361,   361,   337,  1854,   403,   404,   405,   406,
     407,   408,   345,    25,   336,   337,  1865,   339,   337,   336,
     337,   418,   339,   345,   343,   213,    38,    39,   345,    41,
     337,  2328,  1881,  2323,  2324,    25,  2326,  2574,   345,  2329,
      52,    53,    58,    59,  1893,  1894,   337,  2352,    38,    39,
    1899,    41,    88,  1902,   345,  2360,   328,   329,   336,   337,
     357,   339,    52,    53,   361,   337,    25,   345,   336,   337,
     342,   339,   344,  1922,   357,  1924,  2175,   345,   361,    38,
      39,   213,    41,   355,   356,  1960,   358,   359,  1937,  1938,
     404,  1940,  2191,    52,    53,   409,   410,   341,  1947,   338,
    1949,   338,   346,   338,   343,  1954,   343,   338,   343,   338,
     205,   338,   343,   208,   343,  3171,   343,   338,  1967,   338,
    1969,   338,   343,  1972,   343,  2224,   343,   338,  1977,  1978,
     397,  1980,   343,   400,  2980,  2981,   403,   404,   405,   406,
     407,   408,   338,    86,  1993,    88,   393,   343,  2247,  2248,
    1043,  1044,  1045,  1046,  1047,  1048,  1049,  1050,  1051,  1052,
    1053,   375,  3175,   338,   204,  3178,  3179,   266,   343,  3182,
     357,  2046,   397,   360,   361,   400,    56,    57,   403,   404,
     405,   406,   407,   408,   338,   338,   356,   338,   338,   343,
     343,   361,   343,   343,   338,   338,  2045,   357,     4,   343,
     343,     7,     8,     9,   405,   406,  2055,    13,    14,    15,
      16,   338,  2061,    19,    20,    21,   343,    23,    24,   361,
      26,    27,   361,    29,    30,    31,    32,    33,   356,   357,
     338,   338,   397,   398,    40,   343,   343,  2086,   403,   404,
     405,   406,   407,   408,   338,   338,   338,   338,   338,   343,
     343,   343,   343,   343,   202,   159,   204,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    79,   398,   338,   356,   357,   402,  1640,
     343,   397,   398,  2132,   397,  2134,   399,   403,   404,   405,
     406,   407,   408,   338,   356,   338,   354,   338,   343,   361,
     343,  2150,   343,   338,   338,  2154,   179,  2156,   343,   343,
     338,  3174,   338,  1133,   338,   343,  1136,   343,   338,   343,
     338,   338,  2859,   343,   356,   343,   343,   338,   159,   361,
     338,  2180,   343,  3346,   164,   343,   343,   242,   338,  2188,
     270,   348,  2191,   343,   338,  2635,   242,  2637,  2638,   343,
       5,     6,  2201,   356,   338,    10,    11,    12,   361,   343,
     242,   338,    17,    18,   338,  2214,   343,    22,   372,   343,
      25,   343,   338,    28,  2223,   338,   348,   343,   242,    34,
     343,   242,    37,    38,    39,   397,    41,  2236,   156,   157,
    2239,   403,   404,   405,   406,   407,   408,    52,    53,  2505,
     338,   338,  2501,   242,  2253,   343,   343,   397,   398,   202,
     357,   204,  2261,   403,   404,   405,   406,   407,   408,   338,
     338,  2270,   338,   338,   343,   343,   338,   343,   343,    35,
     338,   343,   272,    39,  2533,   343,   338,  3450,   397,   398,
     397,   343,   399,    98,   403,   404,   405,   406,   407,   408,
    2564,   338,    25,   341,   338,  2304,   343,  2306,   346,   343,
    2309,   361,  2576,  2562,  2313,    38,    39,   338,    41,   398,
      25,   398,   343,   402,   398,   402,   199,   200,   402,    52,
      53,  2546,   348,    38,    39,  2550,    41,   398,   348,   398,
     357,   402,  2341,   402,   361,  2344,   348,    52,    53,   342,
     398,   344,   348,  2352,   402,  2354,  2571,   388,   398,  2358,
    2575,  2360,   402,  2578,   397,  2364,   399,  3054,   388,  2368,
    2369,  2370,  3385,  3060,   398,   400,   100,   402,   402,   103,
     104,  2380,  2381,   398,   202,   164,   204,   402,   794,   795,
     796,   797,   202,  2392,   204,   202,   348,   204,   122,   360,
     361,  2400,   132,   348,   202,   135,   204,   294,   295,  3572,
    3573,   141,   342,   348,   344,   174,   175,    81,   142,  2418,
     417,   145,  2671,  2672,   273,   274,   418,   151,   273,   274,
     790,   791,  3638,  2873,   792,   793,   798,   799,   168,  2350,
    2351,  3594,  3595,  3316,  3317,  2470,  2725,  2726,   418,   535,
     416,  3614,  2451,  3698,  3699,  2769,  2770,  3435,  3436,   397,
     190,   417,    41,  2712,   420,  3153,  3154,   923,   924,   193,
     925,   926,  2471,  3481,  3482,   397,   206,   397,  2727,   403,
     397,   413,    55,   106,   398,   414,   402,   217,   218,   219,
    2739,   416,   400,   398,  2493,   402,   111,   348,  2747,   361,
     350,   261,   361,   361,   234,  2504,  2505,   283,   314,  2508,
     252,   241,   242,   243,   238,   290,   241,   247,   314,   284,
     250,  2546,   252,   261,   310,  2550,   256,   261,   135,   337,
     345,   261,  2531,   357,   357,  2534,   353,   337,   333,   336,
     166,   179,   343,  2542,   241,  2544,  2571,   277,   261,   361,
    2575,   135,   260,  2578,   284,   257,  2555,   281,   361,   361,
     166,   216,  2561,  2778,  2563,   289,   296,  2566,  2567,  2568,
    2569,  2570,   106,  2572,   106,  2574,   106,   106,  2577,   106,
    2579,   106,   106,   307,   314,   179,   179,  2802,   257,   357,
     337,   315,   397,   206,   217,   218,  2811,  2596,   403,   404,
     405,   406,   407,   408,   105,   336,   350,  2606,   343,   350,
     337,   234,   235,   418,   246,   420,   345,   343,   241,   242,
     357,   361,   166,   164,   247,   361,   348,   270,   204,   265,
     255,   361,   103,   256,   189,   109,   337,   361,   261,   135,
      34,   418,   416,   416,   398,   141,   361,   361,   337,  2898,
    2649,   361,   361,   135,   277,   361,   126,   361,  2657,   126,
     135,   126,   361,  1633,  1634,  1635,   361,   135,   115,  2918,
    2669,   361,   168,   296,   397,   284,   337,  2676,   164,   283,
     403,   404,   405,   406,   407,   408,   361,   276,   262,   345,
     390,   314,   397,  2692,   233,   357,   312,   385,   403,   404,
     405,   406,   407,   408,   166,   117,   117,   361,  2957,   276,
     164,   164,   347,   337,   348,   348,   356,   356,   241,   261,
     242,   217,   218,   219,   241,  2724,  2975,   217,   242,   242,
     242,   179,  2731,   350,   265,   232,   135,   186,   234,   211,
     109,   246,   337,   343,   265,   241,   242,  2746,   211,   357,
     290,   247,   115,  2778,   250,   257,   361,   356,   227,  2974,
     256,   220,   249,  2762,  2763,   261,  3015,  2766,   204,   397,
     358,   398,   338,  2772,  2773,  2774,   398,  2802,   398,   400,
     348,   277,   338,   337,  2783,  2784,  2811,   358,   284,   246,
    3039,  2790,  3007,  3008,   246,  2794,   254,   358,   361,   121,
     296,   265,   361,   276,   350,  3054,   284,   350,  2807,   211,
     231,  2810,   231,   211,   310,   212,   211,   903,   314,   356,
     211,   314,   103,   104,   115,   361,   361,   211,  2827,   314,
     281,   246,   112,  3048,   112,   361,   180,   345,   180,   350,
     164,  2840,   361,   929,   276,   361,   361,  3062,   261,   935,
     131,   361,   361,   939,  3069,   361,   350,   138,   357,   115,
    2859,   361,  2861,  2862,   145,   361,   361,   270,   356,  2868,
    3119,   115,   361,   133,   164,   358,   157,   361,  2877,  2878,
     245,   152,   109,   343,   210,   340,   263,   379,   338,   170,
     129,   357,   337,  2892,   337,   152,   177,   343,   258,   152,
     361,   357,   147,   261,   261,   343,  3155,   261,   246,   105,
     343,  2910,   200,   357,  2913,  3164,   350,   357,   357,   361,
     361,   154,   345,   166,   276,   179,  2925,   236,   338,   337,
     337,   113,   211,   361,   115,   357,   337,   343,   343,   220,
     201,   206,   223,   246,  3193,   109,   257,   384,   246,  2974,
     242,   284,   233,   384,   358,   337,  1042,  1043,  1044,  1045,
    1046,  1047,  1048,  1049,  1050,  1051,  1052,  1053,   398,   358,
     356,   400,   195,   361,   255,   356,   135,   356,   356,  3194,
     350,  3230,  3007,  3008,  1070,   252,   267,   337,   183,   195,
     358,   293,   356,   309,   356,   361,   268,  2996,  2997,   358,
     361,   356,   242,   284,   246,  3004,   257,   358,   361,   168,
     358,  3267,   358,   356,   189,   109,   356,   358,   231,   356,
     231,  3236,  3237,  3048,   239,   306,   361,  1113,   109,  1999,
     361,   109,   152,   265,   109,   345,   337,  3062,   338,   338,
     278,   345,   179,  3042,  3069,   179,  3045,   246,  3047,   345,
     337,  3050,  3051,   348,   348,  3054,   258,  3056,   217,   154,
     337,  3060,   337,   105,  3063,  3064,   258,  3066,   166,   166,
     220,  3070,   361,   145,   286,   234,   235,  3292,   361,   360,
     361,   174,  3331,   242,  3083,   220,   338,   356,   247,  3088,
     356,   299,   208,   114,   180,   336,   224,   256,    36,   358,
     358,   112,   261,   358,   314,   252,  3105,  3106,   358,   356,
     356,   337,   183,   183,   314,   337,   284,   337,   343,   246,
     246,   246,  3121,  3122,   204,   284,   343,  3342,   356,   265,
     337,   345,   356,   174,  3383,   356,   345,   296,   343,   343,
     343,   357,   361,   361,   307,   109,   337,   195,   337,  3174,
     195,   310,   257,  3152,   164,   314,   357,   211,   338,   337,
     337,   340,   171,   361,   361,   337,   356,   361,   361,  3194,
     356,   129,   357,   361,   361,   258,  3175,  3176,   361,  3178,
    3179,   357,   166,  3182,  3183,  3184,   357,   361,   357,  3404,
     257,   345,   343,  3442,   338,   350,   345,   338,   289,   361,
     246,   343,   361,   356,   337,  3454,  3205,   164,   348,   191,
     236,  3236,  3237,  3462,  3463,  3464,  3465,  3216,   337,   343,
     338,   343,   337,  3222,  1310,   338,  3225,  3476,   109,   337,
     270,   337,   283,  1319,   418,  3234,  3235,   358,   345,   356,
     236,   236,   356,   109,   231,   257,   338,   356,   337,   361,
     361,   361,   152,  3252,   179,   115,  3255,   361,   361,  3258,
    1346,   265,   265,   207,  3263,  3264,   345,  3292,  3267,   337,
     117,   170,   337,   361,  3273,   337,   337,   343,   337,   343,
    3279,   246,  3281,   254,   286,   345,   242,   190,   180,   336,
     235,   348,   350,   348,   201,   348,  3545,   349,   348,   348,
     148,   211,   257,   347,  3303,   348,   337,   337,   337,   348,
     348,   348,   348,   348,   348,   348,  3565,  3342,   343,   137,
     200,   338,   137,   179,   343,   338,   211,   115,  1414,   361,
     357,   137,  3581,   357,   356,   358,  3585,   109,   271,   109,
     356,   361,   356,   227,   338,   207,   115,  3346,   337,   182,
     338,   209,  3351,  2323,  2324,   361,  2326,   385,   115,  2329,
    3385,   265,   171,  3362,   361,   350,   236,   382,   337,   361,
     149,   262,   262,   114,   262,   348,   245,   152,   348,  3404,
     348,   246,  3381,   350,   192,  3384,  3635,  3386,   348,   348,
       5,     6,   345,   109,   262,    10,    11,    12,  3397,   350,
    3399,   348,    17,    18,   350,   348,  3655,    22,   337,   284,
      25,   338,   314,    28,   271,   338,   211,  3666,   358,    34,
    3419,  3420,    37,    38,    39,   205,    41,   109,   337,   361,
     343,   343,   338,   338,   115,   343,   337,    52,    53,   361,
     338,   338,   337,  3692,   115,   172,   192,   239,   337,   343,
    3449,  3450,   211,   152,   180,   338,  3455,   152,   336,  3458,
     336,   348,   311,   356,   192,   361,   262,   284,   314,     4,
    3469,   211,     7,     8,     9,  3474,   223,   356,    13,    14,
      15,    16,   314,   109,    19,    20,    21,  3486,    23,    24,
     361,    26,    27,   338,    29,    30,    31,    32,    33,   351,
     179,   179,   357,   356,   338,    40,  3531,   211,   337,   262,
     124,   361,   356,   343,   299,   358,   337,   242,   338,   361,
    3519,   348,   338,   152,  1610,   249,   118,  3526,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,   348,   179,   334,   152,   348,
     348,   348,   206,   115,   337,   348,   356,   351,   348,   348,
    3559,   337,   246,   337,   337,   252,   200,   345,   105,   337,
     183,   338,   338,  3572,  3573,   361,   338,   337,   343,  3578,
     204,   337,   337,   152,   348,   118,   334,  3586,  3587,   173,
     348,   345,   245,  3592,   338,   175,   164,   246,   361,   348,
     361,   313,   338,   348,   204,   348,   345,  3606,   337,   211,
    1696,   314,   343,   348,   337,  3614,  1702,   338,   338,   338,
     236,   343,   244,   338,   175,  3624,   211,   337,   258,   337,
     258,   338,   337,   109,   348,  3634,   338,   348,   338,   244,
     337,   333,    53,   361,   800,  3644,   803,   805,   333,   801,
     115,   132,  1133,   110,   802,   821,   394,  1084,   804,  3658,
      96,   359,  1018,   613,    96,  2635,   418,  2637,  2638,   687,
     166,  2428,   658,  1894,  1013,  2717,  3675,  2494,  2754,  2715,
    2380,   854,  1735,  3682,     4,     5,     6,     7,     8,     9,
      10,    11,    12,    13,    14,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,    27,    28,    29,
      30,    31,    32,    33,    34,   854,   854,    37,    38,    39,
      40,    41,  3468,  3203,  1746,  2888,  3281,  2656,  3105,  2877,
     875,  1312,    52,    53,  3367,  3209,  3430,  1265,  3275,  1581,
    3119,  3406,  2154,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    77,    78,    79,
    2146,  2045,  2409,  3131,  3129,  2695,   153,  1940,  1854,  1820,
    3606,  1483,  2739,  2750,  2783,  3328,  2531,  3569,    98,  1865,
    3331,  1941,   397,  1832,   192,  1557,  1934,  1069,   403,   404,
     405,   406,   407,   408,   722,  1834,  3456,  3642,  3526,  3675,
    3697,  3183,   934,   418,  3463,   420,  3581,  3585,     7,     8,
       9,  3585,  3465,  1899,    13,    14,  3014,    16,  2780,  3012,
      19,    20,  1967,  1962,    23,    24,   922,  3442,    27,  2283,
    3020,    30,    31,    32,    33,  3158,  1922,  1340,   643,  1824,
      39,    40,  1340,  3155,  3437,  2621,  1969,  1835,  2861,  1980,
    2566,  3258,  1938,  3072,  1940,  1025,  3041,  1024,  2815,  3040,
    3544,  2140,  2170,  1289,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,  1967,  1300,  2139,  2111,   420,  1972,   895,  3145,  2172,
    2162,  2388,  2863,  2320,  2940,  3148,  2458,  2713,  3408,    -1,
      -1,  1434,    -1,  2873,    -1,    -1,    -1,  1993,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      -1,    -1,    37,    38,    39,    40,    41,    -1,  1101,  2045,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    52,    53,  2055,
      -1,    -1,    -1,    -1,    -1,  2061,    -1,    -1,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    98,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,  2150,    -1,    -1,    -1,  2154,    -1,
    2156,    -1,    -1,    -1,    -1,    -1,    -1,   397,    -1,    -1,
      -1,    -1,    -1,   403,   404,   405,   406,   407,   408,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   418,   419,
     420,    -1,  2188,    -1,    -1,     7,     8,     9,    -1,    -1,
      -1,    13,    14,    -1,    16,  2201,    -1,    19,    20,    -1,
      -1,    23,    24,    -1,    -1,    27,    -1,    -1,    30,    31,
      32,    33,    -1,    -1,    -1,    -1,    -1,  2223,    40,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   132,
      -1,    -1,   135,  2239,    -1,    -1,    -1,    -1,   141,    -1,
      -1,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,    73,    74,    75,    76,    77,    78,    79,    -1,    -1,
      82,    83,    84,    -1,  2270,    -1,    -1,    -1,    90,    91,
      92,    93,    94,    95,    -1,    -1,    -1,    -1,   397,    -1,
      -1,    -1,    -1,    -1,    -1,   404,    -1,   190,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   416,    -1,    -1,
    2306,    -1,    -1,   206,    -1,    -1,    -1,  2313,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   218,   219,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   234,    -1,    -1,    -1,    -1,    -1,    -1,   241,   242,
     243,    -1,    -1,    -1,   247,    -1,  2352,    -1,    -1,   252,
      -1,    -1,  2358,   256,  2360,    -1,    -1,    -1,   261,    -1,
      -1,    -1,  2368,     7,     8,     9,    -1,    -1,    -1,    13,
      14,    -1,    16,    -1,   277,    19,    20,    -1,    -1,    23,
      24,   284,    -1,    27,    -1,    -1,    30,    31,    32,    33,
      -1,    -1,   397,   296,    -1,    -1,    40,    -1,   403,   404,
     405,   406,   407,   408,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   314,  2418,   418,   419,   420,    -1,    -1,    -1,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    -1,    -1,    82,    83,
      84,    -1,    -1,    -1,    -1,    -1,    90,    91,    92,    93,
      94,    95,    -1,    -1,    -1,    -1,    -1,    -1,   361,    -1,
      -1,    -1,    -1,    -1,    -1,  2471,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,     7,     8,     9,    -1,    -1,    -1,    13,    14,    -1,
      16,    -1,    -1,    19,    20,    -1,    -1,    23,    24,    -1,
      -1,    27,  2508,    -1,    30,    31,    32,    33,    -1,    -1,
      -1,    -1,    -1,    -1,    40,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,  2531,    -1,    -1,  2534,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,  2542,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    79,    -1,    -1,    82,    83,    84,    -1,
      -1,    -1,    -1,    -1,    90,    91,    92,    93,    94,    95,
       7,     8,     9,    -1,    -1,    -1,    13,    14,    -1,    16,
      -1,    -1,    19,    20,    -1,    -1,    23,    24,    -1,    -1,
      27,    -1,    -1,    30,    31,    32,    33,   419,    -1,    -1,
      -1,    -1,    -1,    40,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    63,    64,    65,    66,
      67,    68,    69,    70,    71,    72,    73,    74,    75,    76,
      77,    78,    79,  2649,    -1,    82,    83,    84,    -1,    -1,
      -1,    -1,    -1,    90,    91,    92,    93,    94,    95,    -1,
      -1,    -1,    -1,  2669,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,     0,    -1,
      -1,     3,     4,    -1,    -1,     7,     8,     9,    -1,    -1,
      -1,    13,    14,    15,    16,    -1,    -1,    19,    20,    21,
      -1,    23,    24,    -1,    26,    27,    -1,    29,    30,    31,
      32,    33,    -1,    -1,    -1,    -1,    -1,    39,    40,    -1,
      -1,    -1,    -1,    -1,    -1,  2731,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    2746,    63,    64,    65,    66,    67,    68,    69,    70,    71,
      72,    73,    74,    75,    76,    77,    78,    79,    -1,    -1,
      82,    83,    84,    -1,    -1,    -1,    -1,    -1,    90,    91,
      92,    93,    94,    95,    -1,   419,    98,  2783,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,  2807,    -1,    -1,    -1,    -1,    -1,    -1,     3,     4,
      -1,    -1,     7,     8,     9,    -1,    -1,    -1,    13,    14,
      15,    16,    -1,    -1,    19,    20,    21,    -1,    23,    24,
      -1,    26,    27,    -1,    29,    30,    31,    32,    33,    -1,
      -1,    -1,    -1,    -1,    39,    40,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,  2859,    -1,    -1,  2862,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    63,    64,
      65,    66,    67,    68,    69,    70,    71,    72,    73,    74,
      75,    76,    77,    78,    79,    -1,  2892,    82,    83,    84,
      -1,    -1,    -1,   419,    -1,    90,    91,    92,    93,    94,
      95,    -1,    -1,    98,     7,     8,     9,    -1,    -1,    -1,
      13,    14,    -1,    16,    -1,    -1,    19,    20,    -1,    -1,
      23,    24,    25,    -1,    27,    -1,    -1,    30,    31,    32,
      33,    -1,    -1,    -1,    -1,    38,    39,    40,    41,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    52,
      53,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,    77,    78,    79,     7,     8,     9,
      -1,    -1,   419,    13,    14,    -1,    16,    -1,    -1,    19,
      20,    -1,    -1,    23,    24,    -1,    -1,    27,    -1,    -1,
      30,    31,    32,    33,    -1,    -1,    -1,    -1,    -1,    39,
      40,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    77,    78,    79,
      -1,    -1,    -1,    -1,     7,     8,     9,  3063,    -1,    -1,
      13,    14,    -1,    16,    -1,    -1,    19,    20,    -1,    -1,
      23,    24,    -1,    -1,    27,   397,    -1,    30,    31,    32,
      33,    -1,   404,    -1,    -1,    -1,    39,    40,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,    77,    78,    79,     7,     8,     9,
      -1,    -1,    -1,    13,    14,    -1,    16,    -1,    -1,    19,
      20,    -1,    -1,    23,    24,    -1,    -1,    27,    -1,    -1,
      30,    31,    32,    33,    -1,    -1,    -1,    -1,    -1,    -1,
      40,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
    3176,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    63,    64,    65,    66,    67,    68,    69,
      70,    71,    72,    73,    74,    75,    76,    77,    78,    79,
      -1,    -1,   397,    -1,    -1,    -1,    -1,    -1,    -1,   404,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,  3252,    -1,    -1,    -1,
      -1,    -1,  3258,     7,     8,     9,    -1,    -1,    -1,    13,
      14,    -1,    16,    -1,    -1,    19,    20,    -1,    -1,    23,
      24,    -1,    -1,    27,    -1,  3281,    30,    31,    32,    33,
      -1,    -1,    -1,    -1,    -1,    -1,    40,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   397,    -1,    -1,    -1,    -1,    -1,
     403,   404,   405,   406,   407,   408,    -1,    -1,    -1,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,     7,     8,     9,    -1,
      -1,    -1,    13,    14,    -1,    16,    -1,    -1,    19,    20,
      -1,    -1,    23,    24,    -1,  3351,    27,    -1,    -1,    30,
      31,    32,    33,    -1,    -1,    -1,    -1,    -1,    -1,    40,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   397,   398,   399,
      -1,    -1,    -1,    -1,   404,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    63,    64,    65,    66,    67,    68,    69,    70,
      71,    72,    73,    74,    75,    76,    77,    78,    79,     7,
       8,     9,    -1,    -1,    -1,    13,    14,    -1,    16,    -1,
      -1,    19,    20,    -1,    -1,    23,    24,    -1,    -1,    27,
      -1,    -1,    30,    31,    32,    33,    -1,    -1,    -1,    -1,
      -1,    -1,    40,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,  3449,   397,    -1,   399,    -1,    -1,  3455,
      -1,   404,  3458,    -1,    -1,    63,    64,    65,    66,    67,
      68,    69,    70,    71,    72,    73,    74,    75,    76,    77,
      78,    79,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,  3519,    -1,    -1,    -1,   397,   398,   399,
    3526,    -1,    -1,    -1,   404,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   102,    -1,
      -1,    -1,    -1,   107,   108,    -1,    -1,   111,   112,    -1,
      -1,    -1,    -1,    -1,   118,   119,    -1,   121,   122,    -1,
     124,    -1,   126,    -1,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,  3578,    -1,    -1,   139,    -1,   141,   142,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,   162,   163,
    3606,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     184,   185,   186,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,    -1,   200,    -1,  3644,    -1,
      -1,   205,    -1,   397,    -1,   399,    -1,    -1,   212,    -1,
     404,   215,  3658,    -1,    -1,   219,   220,   221,   222,    -1,
      -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,  3675,
     234,    -1,    -1,    -1,   238,    -1,  3682,   241,    -1,    -1,
     244,    -1,    -1,    -1,   248,   249,   250,   251,    -1,    -1,
     254,    -1,    -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   268,   269,   270,   271,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   281,    -1,    -1,
      -1,    -1,    -1,   404,    -1,    -1,   290,    -1,   292,    -1,
      -1,    -1,    -1,    -1,   298,   299,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   316,   317,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,    -1,    -1,    -1,    -1,   342,    -1,
     344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,
     398,   355,   356,   357,   358,   359,   360,   361,    -1,    -1,
      -1,    -1,    -1,   367,    -1,   369,   370,    -1,    -1,    -1,
      -1,    -1,    -1,   377,   102,    -1,    -1,   381,    -1,   107,
     108,    -1,    -1,   111,   112,   389,    -1,    -1,    -1,    -1,
     118,   119,   396,   121,   122,    -1,   124,    -1,   126,    -1,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
      -1,   139,    -1,   141,   142,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,
      -1,    -1,   160,    -1,   162,   163,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,   186,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,    -1,   200,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,    -1,    -1,   212,    -1,    -1,   215,    -1,    -1,
      -1,   219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
     248,   249,   250,   251,    -1,    -1,   254,    -1,    -1,   257,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     268,   269,   270,   271,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   281,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,    -1,    -1,    -1,    -1,
     298,   299,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   316,   317,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,
      -1,    -1,    -1,    -1,   342,    -1,   344,    -1,    -1,    -1,
      -1,    -1,    -1,   104,   352,    -1,    -1,   355,   356,   357,
     358,   359,   360,   361,    -1,    -1,    -1,    -1,    -1,   367,
     121,   369,   370,   124,   125,    -1,   127,    -1,    -1,   377,
     131,    -1,    -1,   381,    -1,   136,   137,   138,   139,    -1,
      -1,   389,   143,    -1,   145,   146,    -1,    -1,    -1,    -1,
      -1,    -1,   153,    -1,    -1,    -1,   157,    -1,    -1,    -1,
     161,    -1,    -1,   164,    -1,    -1,    -1,    -1,    -1,   170,
      -1,    -1,    -1,    -1,    -1,    -1,   177,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   193,   194,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   225,    -1,   227,   228,    -1,   230,
      -1,   232,   233,    -1,    -1,   236,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   253,    -1,   255,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   265,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   289,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   300,
     301,    -1,    -1,    -1,    -1,   306,    -1,   102,    -1,    -1,
      -1,    -1,   107,   108,   315,    -1,   111,   112,    -1,    -1,
     321,   322,    -1,    -1,   119,    -1,   121,   122,    -1,   124,
      -1,   126,    -1,    -1,    -1,    -1,   337,   132,    -1,    -1,
      -1,    -1,    -1,   138,   139,    -1,   141,   142,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,
     361,    -1,   363,    -1,   365,   366,    -1,   162,   163,    -1,
     371,    -1,    -1,    -1,    -1,   376,    -1,    -1,    -1,    -1,
      -1,    -1,   383,    -1,    -1,   386,    -1,    -1,    -1,   184,
     185,    -1,   187,    -1,   189,    -1,   191,    -1,   193,   194,
     195,    -1,   197,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     205,    -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,    -1,
     215,    -1,    -1,    -1,   219,   220,   221,   222,    -1,    -1,
      -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,   234,
      -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,
      -1,    -1,    -1,    -1,   249,   250,    -1,    -1,    -1,   254,
      -1,    -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   268,   269,   270,   271,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   280,   281,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   292,    -1,    -1,
      -1,    -1,    -1,    -1,   299,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,
     102,    -1,    -1,    -1,    -1,   107,   108,    -1,    -1,   111,
     112,    -1,    -1,    -1,    -1,    -1,    -1,   119,    -1,   121,
     122,    -1,   124,    -1,   126,    -1,   341,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,    -1,   138,   139,    -1,   141,
     142,    -1,    -1,    -1,    -1,   360,   361,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   374,
     162,   163,   377,    -1,    -1,    -1,   381,   382,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   184,   185,    -1,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,
     212,    -1,    -1,   215,    -1,    -1,    -1,   219,   220,   221,
     222,    -1,    -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,    -1,    -1,    -1,    -1,   249,   250,    -1,
      -1,    -1,   254,    -1,    -1,   257,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   268,   269,   270,   271,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,   281,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     292,    -1,    -1,    -1,    -1,    -1,    -1,   299,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     312,   313,    -1,   102,    -1,    -1,    -1,    -1,   107,   108,
      -1,    -1,   111,   112,    -1,    -1,    -1,    -1,    -1,    -1,
     119,    -1,   121,   122,    -1,   124,    -1,   126,    -1,   341,
      -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,   138,
     139,    -1,   141,   142,    -1,    -1,    -1,    -1,   360,   361,
      -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   374,   162,   163,   377,    -1,    -1,    -1,   381,
     382,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   184,   185,    -1,   187,    -1,
     189,    -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,
      -1,    -1,    -1,   212,    -1,    -1,   215,    -1,    -1,    -1,
     219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,    -1,
     229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,
      -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,    -1,
     249,   250,    -1,    -1,    -1,   254,    -1,    -1,   257,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   268,
     269,   270,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   280,   281,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   292,    -1,    -1,    -1,    -1,    -1,    -1,
     299,    -1,    -1,    -1,    -1,    -1,   102,   103,    -1,    -1,
      -1,   107,   108,   312,   313,   111,   112,    -1,    -1,    -1,
      -1,    -1,   118,   119,    -1,   121,   122,    -1,   124,    -1,
     126,    -1,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,    -1,    -1,   139,    -1,   141,   142,    -1,   144,    -1,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,   360,   361,    -1,   160,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   374,    -1,    -1,   377,    -1,
      -1,    -1,   381,   382,    -1,    -1,    -1,    -1,   184,   185,
     186,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,   199,   200,    -1,    -1,    -1,    -1,   205,
      -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,    -1,   215,
      -1,    -1,    -1,   219,   220,   221,   222,    -1,    -1,    -1,
      -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,   248,   249,   250,   251,   252,    -1,   254,    -1,
      -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   268,   269,   270,   271,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   280,   281,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   290,    -1,   292,    -1,    -1,    -1,
      -1,    -1,   298,   299,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     316,   317,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   337,   338,    -1,    -1,   341,   342,    -1,   344,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,    -1,   355,
     356,   357,   358,   359,   360,   361,    -1,    -1,    -1,    -1,
      -1,   367,    -1,   369,   102,   103,    -1,    -1,    -1,   107,
     108,   377,    -1,   111,   112,   381,    -1,    -1,    -1,    -1,
     118,   119,    -1,   121,   122,    -1,   124,    -1,   126,    -1,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
      -1,   139,    -1,   141,   142,    -1,   144,    -1,    -1,    -1,
      -1,    -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,
      -1,    -1,   160,    -1,   162,   163,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,   186,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,   199,   200,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,    -1,    -1,   212,    -1,    -1,   215,    -1,    -1,
      -1,   219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
     248,   249,   250,   251,   252,    -1,   254,    -1,    -1,   257,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     268,   269,   270,   271,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   280,   281,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,    -1,    -1,    -1,    -1,
     298,   299,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   316,   317,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,
     338,    -1,    -1,   341,   342,    -1,   344,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   352,    -1,    -1,   355,   356,   357,
     358,   359,   360,   361,    -1,    -1,    -1,    -1,   102,   367,
      -1,   369,    -1,   107,   108,    -1,    -1,   111,   112,   377,
      -1,    -1,    -1,   381,   118,   119,    -1,   121,   122,    -1,
     124,    -1,   126,    -1,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,    -1,    -1,    -1,   139,    -1,   141,   142,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,   162,   163,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     184,   185,   186,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,   199,   200,    -1,    -1,    -1,
      -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,
      -1,   215,    -1,    -1,    -1,   219,   220,   221,   222,    -1,
      -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,
     234,    -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,
     244,    -1,    -1,    -1,   248,   249,   250,   251,   252,    -1,
     254,    -1,    -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   265,    -1,    -1,   268,   269,   270,   271,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   280,   281,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,
      -1,    -1,    -1,    -1,   298,   299,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   316,   317,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,   338,    -1,    -1,    -1,   342,    -1,
     344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,
      -1,   355,   356,   357,   358,   359,   360,   361,    -1,    -1,
      -1,    -1,   102,   367,    -1,   369,    -1,   107,   108,    -1,
      -1,   111,   112,   377,    -1,    -1,    -1,   381,   118,   119,
      -1,   121,   122,    -1,   124,    -1,   126,    -1,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,    -1,   139,
      -1,   141,   142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   151,    -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,
     160,    -1,   162,   163,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   184,   185,   186,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,   199,
     200,    -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,
      -1,    -1,   212,    -1,    -1,   215,    -1,    -1,    -1,   219,
     220,   221,   222,    -1,    -1,    -1,    -1,    -1,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,   248,   249,
     250,   251,   252,    -1,   254,    -1,    -1,   257,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   265,    -1,    -1,   268,   269,
     270,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     280,   281,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,    -1,    -1,    -1,    -1,   298,   299,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   312,   313,    -1,    -1,   316,   317,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,    -1,    -1,
      -1,    -1,   342,    -1,   344,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   352,    -1,    -1,   355,   356,   357,   358,   359,
     360,   361,    -1,    -1,    -1,    -1,   102,   367,    -1,   369,
      -1,   107,   108,    -1,    -1,   111,   112,   377,    -1,    -1,
      -1,   381,   118,   119,    -1,   121,   122,    -1,   124,    -1,
     126,    -1,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,    -1,    -1,   139,    -1,   141,   142,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,    -1,    -1,    -1,   160,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   184,   185,
     186,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,   199,   200,    -1,    -1,    -1,    -1,   205,
      -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,    -1,   215,
      -1,    -1,    -1,   219,   220,   221,   222,    -1,    -1,    -1,
      -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,   248,   249,   250,   251,   252,    -1,   254,    -1,
      -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   268,   269,   270,   271,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   280,   281,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   290,    -1,   292,    -1,    -1,    -1,
      -1,    -1,   298,   299,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     316,   317,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   337,   338,    -1,    -1,    -1,   342,    -1,   344,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,    -1,   355,
     356,   357,   358,   359,   360,   361,    -1,    -1,    -1,    -1,
     102,   367,    -1,   369,    -1,   107,   108,    -1,    -1,   111,
     112,   377,    -1,    -1,    -1,   381,   118,   119,    -1,   121,
     122,    -1,   124,    -1,   126,    -1,    -1,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,    -1,    -1,   139,    -1,   141,
     142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,
     162,   163,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   184,   185,   186,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,   199,   200,    -1,
      -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,
     212,    -1,    -1,   215,    -1,    -1,    -1,   219,   220,   221,
     222,    -1,    -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,    -1,    -1,    -1,   248,   249,   250,   251,
     252,    -1,   254,    -1,    -1,   257,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   268,   269,   270,   271,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,   281,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,    -1,    -1,    -1,    -1,   298,   299,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     312,   313,    -1,    -1,   316,   317,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   337,    -1,    -1,    -1,   341,
     342,    -1,   344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     352,    -1,    -1,   355,   356,   357,   358,   359,   360,   361,
      -1,    -1,    -1,    -1,   102,   367,    -1,   369,    -1,   107,
     108,    -1,    -1,   111,   112,   377,    -1,    -1,    -1,   381,
     118,   119,    -1,   121,   122,    -1,   124,    -1,   126,    -1,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
      -1,   139,    -1,   141,   142,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,
      -1,    -1,   160,    -1,   162,   163,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,   186,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,   199,   200,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,    -1,    -1,   212,    -1,    -1,   215,    -1,    -1,
      -1,   219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
     248,   249,   250,   251,   252,    -1,   254,    -1,    -1,   257,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     268,   269,   270,   271,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   280,   281,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,    -1,    -1,    -1,    -1,
     298,   299,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   316,   317,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,
     338,    -1,    -1,    -1,   342,    -1,   344,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   352,    -1,    -1,   355,   356,   357,
     358,   359,   360,   361,    -1,    -1,    -1,    -1,   102,   367,
      -1,   369,    -1,   107,   108,    -1,    -1,   111,   112,   377,
      -1,    -1,    -1,   381,   118,   119,    -1,   121,   122,    -1,
     124,    -1,   126,    -1,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,    -1,    -1,    -1,   139,    -1,   141,   142,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,   162,   163,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     184,   185,   186,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,   199,   200,    -1,    -1,    -1,
      -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,
      -1,   215,    -1,    -1,    -1,   219,   220,   221,   222,    -1,
      -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,
     234,    -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,
     244,    -1,    -1,    -1,   248,   249,   250,   251,   252,    -1,
     254,    -1,    -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   268,   269,   270,   271,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   280,   281,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,
      -1,    -1,    -1,    -1,   298,   299,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   316,   317,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,   338,    -1,    -1,    -1,   342,    -1,
     344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,
      -1,   355,   356,   357,   358,   359,   360,   361,    -1,    -1,
      -1,    -1,   102,   367,    -1,   369,    -1,   107,   108,    -1,
      -1,   111,   112,   377,    -1,    -1,    -1,   381,   118,   119,
      -1,   121,   122,    -1,   124,    -1,   126,    -1,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,    -1,   139,
      -1,   141,   142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   151,    -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,
     160,    -1,   162,   163,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   184,   185,   186,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,   199,
     200,    -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,
      -1,    -1,   212,    -1,    -1,   215,    -1,    -1,    -1,   219,
     220,   221,   222,    -1,    -1,    -1,    -1,    -1,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,   248,   249,
     250,   251,   252,    -1,   254,    -1,    -1,   257,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   268,   269,
     270,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     280,   281,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,    -1,    -1,    -1,    -1,   298,   299,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   312,   313,    -1,    -1,   316,   317,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,   338,    -1,
      -1,    -1,   342,    -1,   344,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   352,    -1,    -1,   355,   356,   357,   358,   359,
     360,   361,    -1,    -1,    -1,    -1,   102,   367,    -1,   369,
      -1,   107,   108,    -1,    -1,   111,   112,   377,    -1,    -1,
      -1,   381,   118,   119,    -1,   121,   122,    -1,   124,    -1,
     126,    -1,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,    -1,    -1,   139,    -1,   141,   142,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,    -1,    -1,    -1,   160,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   184,   185,
     186,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,   199,   200,    -1,    -1,    -1,    -1,   205,
      -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,    -1,   215,
      -1,    -1,    -1,   219,   220,   221,   222,    -1,    -1,    -1,
      -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,   248,   249,   250,   251,   252,    -1,   254,    -1,
      -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   268,   269,   270,   271,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   280,   281,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   290,    -1,   292,    -1,    -1,    -1,
      -1,    -1,   298,   299,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     316,   317,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   337,    -1,    -1,    -1,    -1,   342,    -1,   344,    -1,
      -1,    -1,   348,    -1,    -1,    -1,   352,    -1,    -1,   355,
     356,   357,   358,   359,   360,   361,    -1,    -1,    -1,    -1,
     102,   367,    -1,   369,    -1,   107,   108,    -1,    -1,   111,
     112,   377,    -1,    -1,    -1,   381,   118,   119,    -1,   121,
     122,    -1,   124,    -1,   126,    -1,    -1,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,    -1,    -1,   139,    -1,   141,
     142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,
     162,   163,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   184,   185,   186,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,   199,   200,    -1,
      -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,
     212,    -1,    -1,   215,    -1,    -1,    -1,   219,   220,   221,
     222,    -1,    -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,    -1,    -1,    -1,   248,   249,   250,   251,
     252,    -1,   254,    -1,    -1,   257,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   268,   269,   270,   271,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   280,   281,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,    -1,    -1,    -1,    -1,   298,   299,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     312,   313,    -1,    -1,   316,   317,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   337,    -1,    -1,    -1,    -1,
     342,    -1,   344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     352,    -1,    -1,   355,   356,   357,   358,   359,   360,   361,
      -1,    -1,    -1,    -1,   102,   367,    -1,   369,    -1,   107,
     108,    -1,    -1,   111,   112,   377,    -1,    -1,    -1,   381,
     118,   119,    -1,   121,   122,    -1,   124,    -1,   126,    -1,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
      -1,   139,    -1,   141,   142,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,
      -1,    -1,   160,    -1,   162,   163,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,   186,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,    -1,   200,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,    -1,    -1,   212,    -1,    -1,   215,    -1,    -1,
      -1,   219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
     248,   249,   250,   251,   252,    -1,   254,    -1,    -1,   257,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     268,   269,   270,   271,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   280,   281,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,    -1,    -1,    -1,    -1,
     298,   299,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   316,   317,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,
      -1,    -1,    -1,    -1,   342,    -1,   344,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   352,    -1,    -1,   355,   356,   357,
     358,   359,   360,   361,    -1,    -1,    -1,    -1,   102,   367,
      -1,   369,    -1,   107,   108,    -1,    -1,   111,   112,   377,
      -1,    -1,    -1,   381,   118,   119,    -1,   121,   122,    -1,
     124,    -1,   126,    -1,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,    -1,    -1,    -1,   139,    -1,   141,   142,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,   162,   163,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     184,   185,   186,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,    -1,   200,    -1,    -1,    -1,
      -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,
      -1,   215,    -1,    -1,    -1,   219,   220,   221,   222,    -1,
      -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,
     234,    -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,
     244,    -1,    -1,    -1,   248,   249,   250,   251,    -1,    -1,
     254,    -1,    -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   268,   269,   270,   271,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   281,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,
      -1,    -1,    -1,    -1,   298,   299,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   316,   317,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,    -1,    -1,    -1,   341,   342,    -1,
     344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,
      -1,   355,   356,   357,   358,   359,   360,   361,    -1,    -1,
      -1,    -1,   102,   367,    -1,   369,    -1,   107,   108,    -1,
      -1,   111,   112,   377,    -1,    -1,    -1,   381,   118,   119,
      -1,   121,   122,    -1,   124,    -1,   126,    -1,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,    -1,   139,
      -1,   141,   142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   151,    -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,
     160,    -1,   162,   163,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   184,   185,   186,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,    -1,
     200,    -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,
      -1,    -1,   212,    -1,    -1,   215,    -1,    -1,    -1,   219,
     220,   221,   222,    -1,    -1,    -1,    -1,    -1,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,   248,   249,
     250,   251,    -1,    -1,   254,    -1,    -1,   257,    -1,    -1,
      -1,    -1,   262,    -1,    -1,    -1,    -1,    -1,   268,   269,
     270,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   281,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,    -1,    -1,    -1,    -1,   298,   299,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   312,   313,    -1,    -1,   316,   317,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,    -1,    -1,
      -1,    -1,   342,    -1,   344,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   352,    -1,    -1,   355,   356,   357,   358,   359,
     360,   361,    -1,    -1,    -1,    -1,   102,   367,    -1,   369,
      -1,   107,   108,    -1,    -1,   111,   112,   377,    -1,    -1,
      -1,   381,   118,   119,    -1,   121,   122,    -1,   124,    -1,
     126,    -1,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,   137,    -1,   139,    -1,   141,   142,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,    -1,    -1,    -1,   160,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   184,   185,
     186,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,    -1,   200,    -1,    -1,    -1,    -1,   205,
      -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,    -1,   215,
      -1,    -1,    -1,   219,   220,   221,   222,    -1,    -1,    -1,
      -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,   248,   249,   250,   251,    -1,    -1,   254,    -1,
      -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   268,   269,   270,   271,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   281,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   290,    -1,   292,    -1,    -1,    -1,
      -1,    -1,   298,   299,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     316,   317,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   337,    -1,    -1,    -1,    -1,   342,    -1,   344,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,    -1,   355,
     356,   357,   358,   359,   360,   361,    -1,    -1,    -1,    -1,
     102,   367,    -1,   369,    -1,   107,   108,    -1,    -1,   111,
     112,   377,    -1,    -1,    -1,   381,   118,   119,    -1,   121,
     122,    -1,   124,    -1,   126,    -1,    -1,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,   137,    -1,   139,    -1,   141,
     142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,
     162,   163,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   184,   185,   186,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,    -1,   200,    -1,
      -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,
     212,    -1,    -1,   215,    -1,    -1,    -1,   219,   220,   221,
     222,    -1,    -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,    -1,    -1,    -1,   248,   249,   250,   251,
      -1,    -1,   254,    -1,    -1,   257,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   268,   269,   270,   271,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   281,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,    -1,    -1,    -1,    -1,   298,   299,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     312,   313,    -1,    -1,   316,   317,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   337,    -1,    -1,    -1,    -1,
     342,    -1,   344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     352,    -1,    -1,   355,   356,   357,   358,   359,   360,   361,
      -1,    -1,    -1,    -1,   102,   367,    -1,   369,    -1,   107,
     108,    -1,    -1,   111,   112,   377,    -1,    -1,    -1,   381,
     118,   119,    -1,   121,   122,    -1,   124,    -1,   126,    -1,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
      -1,   139,    -1,   141,   142,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,
      -1,    -1,   160,    -1,   162,   163,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,   186,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,    -1,   200,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,    -1,    -1,   212,    -1,    -1,   215,    -1,    -1,
      -1,   219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
     248,   249,   250,   251,    -1,    -1,   254,    -1,    -1,   257,
      -1,    -1,    -1,    -1,   262,    -1,    -1,    -1,    -1,    -1,
     268,   269,   270,   271,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   281,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   290,    -1,   292,    -1,    -1,    -1,    -1,    -1,
     298,   299,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   316,   317,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,
      -1,    -1,    -1,    -1,   342,    -1,   344,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   352,    -1,    -1,   355,   356,   357,
     358,   359,   360,   361,    -1,    -1,    -1,    -1,   102,   367,
      -1,   369,    -1,   107,   108,    -1,    -1,   111,   112,   377,
      -1,    -1,    -1,   381,   118,   119,    -1,   121,   122,    -1,
     124,    -1,   126,    -1,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,    -1,   137,    -1,   139,    -1,   141,   142,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,   162,   163,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     184,   185,   186,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,    -1,   200,    -1,    -1,    -1,
      -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,
      -1,   215,    -1,    -1,    -1,   219,   220,   221,   222,    -1,
      -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,
     234,    -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,
     244,    -1,    -1,    -1,   248,   249,   250,   251,    -1,    -1,
     254,    -1,    -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   268,   269,   270,   271,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   281,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,   292,    -1,
      -1,    -1,    -1,    -1,   298,   299,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   316,   317,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   325,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,    -1,    -1,    -1,    -1,   342,    -1,
     344,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,
      -1,   355,   356,   357,   358,   359,   360,   361,    -1,    -1,
      -1,    -1,   102,   367,    -1,   369,    -1,   107,   108,    -1,
      -1,   111,   112,   377,    -1,    -1,    -1,   381,   118,   119,
      -1,   121,   122,    -1,   124,    -1,   126,    -1,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,    -1,   139,
      -1,   141,   142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   151,    -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,
     160,    -1,   162,   163,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   184,   185,   186,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,    -1,
     200,    -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,
      -1,    -1,   212,    -1,    -1,   215,    -1,    -1,    -1,   219,
     220,   221,   222,    -1,    -1,    -1,    -1,    -1,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,   248,   249,
     250,   251,    -1,    -1,   254,    -1,    -1,   257,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   268,   269,
     270,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   281,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     290,    -1,   292,    -1,    -1,    -1,    -1,    -1,   298,   299,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   312,   313,    -1,    -1,   316,   317,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   325,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,    -1,    -1,
      -1,   341,   342,    -1,   344,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   352,    -1,    -1,   355,   356,   357,   358,   359,
     360,   361,    -1,    -1,    -1,    -1,   102,   367,    -1,   369,
      -1,   107,   108,    -1,    -1,   111,   112,   377,    -1,    -1,
      -1,   381,   118,   119,    -1,   121,   122,    -1,   124,    -1,
     126,    -1,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,    -1,    -1,   139,    -1,   141,   142,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,    -1,    -1,    -1,   160,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   184,   185,
     186,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,    -1,   200,    -1,    -1,    -1,    -1,   205,
      -1,    -1,    -1,    -1,    -1,    -1,   212,    -1,    -1,   215,
      -1,    -1,    -1,   219,   220,   221,   222,    -1,    -1,    -1,
      -1,    -1,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,   248,   249,   250,   251,    -1,    -1,   254,    -1,
      -1,   257,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   268,   269,   270,   271,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   281,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   290,    -1,   292,    -1,    -1,    -1,
      -1,    -1,   298,   299,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     316,   317,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   325,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   337,    -1,    -1,    -1,    -1,   342,    -1,   344,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   352,    -1,    -1,   355,
     356,   357,   358,   359,   360,   361,    -1,    -1,    -1,    -1,
     102,   367,    -1,   369,    -1,   107,   108,    -1,    -1,   111,
     112,   377,    -1,    -1,    -1,   381,   118,   119,    -1,   121,
     122,    -1,   124,    -1,   126,    -1,    -1,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,    -1,    -1,   139,    -1,   141,
     142,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,   160,    -1,
     162,   163,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   184,   185,   186,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,    -1,   200,    -1,
      -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,    -1,    -1,
     212,    -1,    -1,    -1,    -1,    -1,    -1,   219,   220,   221,
     222,    -1,    -1,    -1,    -1,    -1,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,    -1,    -1,    -1,   248,   249,   250,   251,
      -1,    -1,   254,    -1,    -1,   257,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   268,   269,   270,   271,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   281,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   290,    -1,
     292,    -1,    -1,    -1,    -1,    -1,   298,   299,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     312,   313,   102,    -1,   316,   317,    -1,   107,   108,    -1,
      -1,   111,   112,   325,    -1,    -1,    -1,    -1,    -1,   119,
      -1,   121,   122,    -1,   124,   337,   126,    -1,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,    -1,   139,
     352,   141,   142,   355,   356,   357,   358,   359,   360,   361,
      -1,   151,    -1,   153,    -1,   367,    -1,   369,    -1,    -1,
      -1,    -1,   162,   163,    -1,   377,    -1,    -1,    -1,   381,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   184,   185,    -1,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,    -1,
     200,    -1,    -1,    -1,    -1,   205,    -1,    -1,    -1,    -1,
      -1,    -1,   212,    -1,    -1,    -1,    -1,    -1,    -1,   219,
     220,   221,   222,    -1,    -1,    -1,    -1,    -1,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,    -1,   249,
     250,    -1,    -1,    -1,   254,    -1,    -1,   257,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   268,   269,
     270,   271,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   281,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   292,    -1,    -1,    -1,    -1,    -1,    -1,   299,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   312,   313,   102,    -1,    -1,    -1,    -1,   107,
     108,    -1,    -1,   111,   112,    -1,    -1,    -1,   328,   329,
      -1,   119,    -1,   121,   122,    -1,   124,   337,   126,    -1,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
      -1,   139,    -1,   141,   142,   355,   356,   357,   358,   359,
     360,   361,    -1,   151,    -1,   153,    -1,   367,    -1,   369,
      -1,    -1,    -1,    -1,   162,   163,    -1,   377,    -1,    -1,
      -1,   381,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,    -1,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,    -1,    -1,   212,    -1,    -1,    -1,    -1,    -1,
      -1,   219,   220,   221,   222,    -1,    -1,    -1,    -1,    -1,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
      -1,   249,   250,    -1,    -1,    -1,   254,    -1,   102,   257,
      -1,    -1,    -1,   107,   108,    -1,    -1,   111,   112,    -1,
     268,   269,   270,   271,    -1,   119,    -1,   121,   122,    -1,
     124,    -1,   126,   281,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,    -1,    -1,   292,   139,    -1,   141,   142,    -1,
      -1,   299,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   162,   163,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
     184,   185,    -1,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,    -1,    -1,    -1,   356,   357,
      -1,   205,   360,   361,    -1,    -1,    -1,    -1,   212,    -1,
      -1,    -1,    -1,    -1,    -1,   219,   220,   221,   222,   377,
      -1,    -1,    -1,   381,    -1,   229,    -1,    -1,    -1,   233,
     234,    -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,
     244,    -1,    -1,    -1,    -1,   249,   250,    -1,    -1,    -1,
     254,    -1,   102,   257,    -1,    -1,    -1,   107,   108,    -1,
      -1,   111,   112,    -1,   268,   269,   270,   271,    -1,   119,
      -1,   121,   122,    -1,   124,    -1,   126,   281,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,   292,   139,
      -1,   141,   142,    -1,    -1,   299,    -1,    -1,    -1,    -1,
      -1,   151,    -1,   153,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   162,   163,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,   184,   185,    -1,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   205,   360,   361,    -1,    -1,
      -1,    -1,   212,    -1,    -1,    -1,    -1,    -1,    -1,   219,
     220,   221,   222,   377,    -1,    -1,    -1,   381,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,    -1,   249,
     250,    -1,    -1,    -1,   254,    -1,   102,   257,    -1,    -1,
      -1,   107,   108,    -1,    -1,   111,   112,    -1,   268,   269,
     270,   271,    -1,   119,    -1,   121,   122,    -1,   124,    -1,
     126,   281,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,    -1,   292,   139,    -1,   141,   142,    -1,    -1,   299,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,    -1,   312,   313,    -1,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   184,   185,
      -1,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,    -1,    -1,    -1,    -1,    -1,   358,   205,
     360,   361,    -1,    -1,    -1,    -1,   212,    -1,    -1,    -1,
      -1,    -1,    -1,   219,   220,   221,   222,   377,    -1,    -1,
      -1,   381,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,    -1,   249,   250,    -1,    -1,    -1,   254,    -1,
     102,   257,    -1,    -1,    -1,   107,   108,    -1,    -1,   111,
     112,    -1,   268,   269,   270,   271,    -1,   119,    -1,   121,
     122,    -1,   124,    -1,   126,   281,   128,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,    -1,   292,   139,    -1,   141,
     142,    -1,    -1,   299,    -1,    -1,    -1,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     162,   163,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,   184,   185,    -1,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,    -1,    -1,    -1,
     356,    -1,    -1,   205,   360,   361,    -1,    -1,    -1,    -1,
     212,    -1,    -1,    -1,    -1,    -1,    -1,   219,   220,   221,
     222,   377,    -1,    -1,    -1,   381,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,    -1,    -1,    -1,    -1,   249,   250,    -1,
      -1,    -1,   254,    -1,   102,   257,    -1,    -1,    -1,   107,
     108,    -1,    -1,   111,   112,    -1,   268,   269,   270,   271,
      -1,   119,    -1,   121,   122,    -1,   124,    -1,   126,   281,
      -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,
     292,   139,    -1,   141,   142,    -1,    -1,   299,    -1,    -1,
      -1,    -1,    -1,   151,    -1,   153,    -1,    -1,    -1,    -1,
     312,   313,    -1,    -1,   162,   163,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   184,   185,    -1,   187,
      -1,   189,    -1,   191,    -1,   193,   194,   195,    -1,   197,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   205,   360,   361,
      -1,    -1,    -1,    -1,   212,    -1,    -1,    -1,    -1,    -1,
      -1,   219,   220,   221,   222,   377,    -1,    -1,    -1,   381,
      -1,   229,    -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,
     238,    -1,    -1,   241,    -1,    -1,   244,    -1,    -1,    -1,
      -1,   249,   250,    -1,    -1,    -1,   254,    -1,   102,   257,
      -1,    -1,    -1,   107,   108,    -1,    -1,   111,   112,    -1,
     268,   269,   270,   271,    -1,   119,    -1,   121,   122,    -1,
     124,    -1,   126,   281,    -1,    -1,    -1,    -1,   132,    -1,
      -1,    -1,    -1,    -1,   292,   139,    -1,   141,   142,    -1,
      -1,   299,    -1,    -1,    -1,    -1,    -1,   151,    -1,   153,
      -1,    -1,    -1,    -1,   312,   313,    -1,    -1,   162,   163,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,
     184,   185,    -1,   187,    -1,   189,    -1,   191,    -1,   193,
     194,   195,    -1,   197,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   205,   360,   361,    -1,    -1,    -1,    -1,   212,    -1,
      -1,    -1,    -1,    -1,    -1,   219,   220,   221,   222,   377,
      -1,    -1,    -1,   381,    -1,   229,    -1,    -1,    -1,    -1,
     234,    -1,    -1,    -1,   238,    -1,    -1,   241,    -1,    -1,
     244,    -1,    -1,    -1,    -1,   249,   250,    -1,    -1,    -1,
     254,    -1,   102,   257,    -1,    -1,    -1,   107,   108,    -1,
      -1,   111,   112,    -1,   268,   269,   270,   271,    -1,   119,
      -1,   121,   122,    -1,   124,    -1,   126,   281,    -1,    -1,
      -1,    -1,   132,    -1,    -1,    -1,    -1,    -1,   292,   139,
      -1,   141,   142,    -1,    -1,   299,    -1,    -1,    -1,    -1,
      -1,   151,    -1,   153,    -1,    -1,    -1,    -1,   312,   313,
      -1,    -1,   162,   163,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   337,   184,   185,    -1,   187,    -1,   189,
      -1,   191,    -1,   193,   194,   195,    -1,   197,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   205,   360,   361,    -1,    -1,
      -1,    -1,   212,    -1,    -1,    -1,    -1,    -1,    -1,   219,
     220,   221,   222,   377,    -1,    -1,    -1,   381,    -1,   229,
      -1,    -1,    -1,    -1,   234,    -1,    -1,    -1,   238,    -1,
      -1,   241,    -1,    -1,   244,    -1,    -1,    -1,    -1,   249,
     250,    -1,    -1,    -1,   254,    -1,   102,   257,    -1,    -1,
      -1,   107,   108,    -1,    -1,   111,   112,    -1,   268,   269,
     270,   271,    -1,   119,    -1,   121,   122,    -1,   124,    -1,
     126,   281,    -1,    -1,    -1,    -1,   132,    -1,    -1,    -1,
      -1,    -1,   292,   139,    -1,   141,   142,    -1,    -1,   299,
      -1,    -1,    -1,    -1,    -1,   151,    -1,   153,    -1,    -1,
      -1,    -1,   312,   313,    -1,    -1,   162,   163,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   337,   184,   185,
      -1,   187,    -1,   189,    -1,   191,    -1,   193,   194,   195,
      -1,   197,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   205,
     360,   361,    -1,    -1,    -1,    -1,   212,    -1,    -1,    -1,
      -1,    -1,    -1,   219,   220,   221,   222,   377,    -1,    -1,
      -1,   381,    -1,   229,    -1,    -1,    -1,    -1,   234,    -1,
      -1,    -1,   238,    -1,    -1,   241,    -1,    -1,   244,    -1,
      -1,    -1,    -1,   249,   250,    -1,    -1,    -1,   254,    -1,
     102,   257,    -1,    -1,    -1,   107,   108,    -1,    -1,   111,
     112,    -1,   268,   269,   270,   271,    -1,   119,    -1,   121,
     122,    -1,   124,    -1,   126,   281,    -1,    -1,    -1,    -1,
     132,    -1,    -1,    -1,    -1,    -1,   292,   139,    -1,   141,
     142,    -1,    -1,   299,    -1,    -1,    -1,    -1,    -1,   151,
      -1,   153,    -1,    -1,    -1,    -1,   312,   313,    -1,    -1,
     162,   163,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   337,   184,   185,    -1,   187,    -1,   189,    -1,   191,
      -1,   193,   194,   195,    -1,   197,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   205,   360,   361,    -1,    -1,    -1,    -1,
     212,    -1,    -1,    -1,    -1,    -1,    -1,   219,   220,   221,
     222,   377,    -1,   104,    -1,   381,    -1,   229,    -1,    -1,
      -1,    -1,   234,    -1,    -1,    -1,   238,    -1,    -1,   241,
      -1,    -1,   244,   124,   125,    -1,    -1,   249,   250,    -1,
     131,    -1,   254,    -1,    -1,   257,   137,   138,   139,    -1,
      -1,    -1,    -1,    -1,   145,    -1,   268,   269,   270,   271,
      -1,    -1,   153,    -1,    -1,    -1,    -1,    -1,    -1,   281,
      -1,    -1,    -1,   164,    -1,    -1,    -1,    -1,    -1,   170,
     292,    -1,    -1,    -1,    -1,    -1,   177,   299,    -1,    -1,
      -1,    -1,    -1,    -1,   104,    -1,    -1,    -1,    -1,    -1,
     312,   313,   193,   194,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,   124,   125,    -1,    -1,    -1,    -1,
      -1,   131,    -1,    -1,    -1,    -1,    -1,   137,   138,   139,
      -1,    -1,    -1,    -1,    -1,   145,   227,   228,    -1,   230,
      -1,   232,   233,   153,    -1,   236,    -1,    -1,   360,   361,
      -1,    -1,    -1,    -1,   164,    -1,    -1,    -1,    -1,    -1,
     170,    -1,    -1,    -1,   255,   377,    -1,   177,    -1,   381,
      -1,    -1,    -1,    -1,   265,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,   193,   194,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   289,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   300,
     301,    -1,    -1,    -1,    -1,   306,    -1,   227,   228,    -1,
     230,    -1,   232,   233,   315,    -1,   236,    -1,    -1,    -1,
     321,   322,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   255,   337,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,   265,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   357,    -1,   104,    -1,
     361,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   114,   289,
      -1,    -1,   118,    -1,    -1,   121,    -1,    -1,    -1,   125,
     300,   301,   383,    -1,   130,    -1,   306,    -1,    -1,    -1,
     136,    -1,   138,    -1,    -1,   315,    -1,    -1,    -1,    -1,
      -1,   321,   322,    -1,    -1,    -1,    -1,   153,    -1,   155,
      -1,    -1,   158,    -1,    -1,   161,    -1,   337,   164,    -1,
      -1,    -1,    -1,   169,    -1,    -1,    -1,   173,    -1,    -1,
      -1,   177,    -1,    -1,    -1,    -1,    -1,   357,    -1,    -1,
      -1,   361,    -1,    -1,    -1,    -1,   192,   193,   194,    -1,
      -1,   104,    -1,    -1,   200,    -1,    -1,    -1,    -1,   205,
      -1,   114,    -1,   383,    -1,   118,    -1,    -1,   121,    -1,
      -1,    -1,   125,    -1,    -1,    -1,    -1,   130,    -1,    -1,
      -1,   227,    -1,   136,   230,   138,   232,   233,    -1,    -1,
     236,    -1,    -1,    -1,    -1,    -1,   104,    -1,    -1,   152,
     153,    -1,    -1,    -1,    -1,   158,   114,    -1,   161,   255,
     118,   164,    -1,   121,    -1,    -1,   169,   125,   264,   265,
     173,    -1,   130,    -1,   177,    -1,    -1,    -1,   136,    -1,
     138,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,   192,
     193,   194,   288,    -1,    -1,   153,    -1,   200,    -1,    -1,
     158,    -1,   205,   161,    -1,    -1,   164,    -1,    -1,    -1,
      -1,   169,    -1,    -1,    -1,   173,    -1,    -1,    -1,   177,
      -1,    -1,    -1,    -1,   227,    -1,    -1,   230,    -1,   232,
     233,    -1,    -1,   236,   192,   193,   194,    -1,    -1,    -1,
      -1,   337,   200,    -1,    -1,    -1,    -1,   205,    -1,    -1,
      -1,    -1,   255,   349,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,   264,   265,    -1,   360,   361,    -1,    -1,    -1,   227,
      -1,    -1,   230,    -1,   232,   233,    -1,    -1,   236,    -1,
      -1,    -1,    -1,    -1,    -1,   288,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   255,    -1,    -1,
       4,    -1,    -1,     7,     8,     9,   264,   265,    -1,    13,
      14,    15,    16,    -1,    -1,    19,    20,    21,    -1,    23,
      24,    -1,    26,    27,    -1,    29,    30,    31,    32,    33,
     288,    -1,    -1,    -1,   337,    -1,    40,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,   349,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,   360,   361,    63,
      64,    65,    66,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    76,    77,    78,    79,    -1,    -1,    -1,   337,
      -1,     7,     8,     9,    -1,    -1,    -1,    13,    14,    -1,
      16,   349,    -1,    19,    20,    -1,    -1,    23,    24,    -1,
      -1,    27,   360,   361,    30,    31,    32,    33,    -1,    35,
      -1,    -1,    -1,    -1,    40,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    63,    64,    65,
      66,    67,    68,    69,    70,    71,    72,    73,    74,    75,
      76,    77,    78,    79,     7,     8,     9,    -1,    -1,    -1,
      13,    14,    -1,    16,    -1,    -1,    19,    20,    -1,    -1,
      23,    24,    -1,    -1,    27,    -1,    -1,    30,    31,    32,
      33,    -1,    -1,    -1,    -1,    -1,    -1,    40,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    -1,
      63,    64,    65,    66,    67,    68,    69,    70,    71,    72,
      73,    74,    75,    76,    77,    78,    79
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
   symbol of state STATE-NUM.  */
static const yytype_uint16 yystos[] =
{
       0,     3,     4,     7,     8,     9,    13,    14,    15,    16,
      19,    20,    21,    23,    24,    26,    27,    29,    30,    31,
      32,    33,    39,    40,    63,    64,    65,    66,    67,    68,
      69,    70,    71,    72,    73,    74,    75,    76,    77,    78,
      79,    82,    83,    84,    90,    91,    92,    93,    94,    95,
      98,   397,   404,   422,   423,   424,   446,   447,   451,   452,
     454,   457,   464,   467,   468,   471,   494,   496,   498,   499,
     500,   501,   502,   503,   504,   505,   506,   507,   508,    80,
      80,   420,   496,    86,    88,    85,    97,    97,    97,    97,
     111,   114,   152,   385,   393,   394,   509,   547,   548,   549,
     550,   467,   452,   471,   472,     0,   423,   418,   448,   450,
     467,   447,   447,   420,   455,   456,   496,   420,   446,   447,
     485,   488,   489,   495,   397,   399,   469,   470,   468,   465,
     466,   496,   420,    89,    89,   357,   361,   136,   136,   337,
     199,   392,   104,   121,   124,   125,   127,   131,   136,   137,
     138,   139,   143,   145,   146,   153,   157,   161,   164,   170,
     177,   193,   194,   205,   225,   227,   228,   230,   232,   233,
     236,   253,   255,   265,   289,   300,   301,   306,   315,   321,
     322,   337,   361,   363,   365,   366,   371,   376,   383,   386,
     510,   511,   512,   519,   520,   521,   525,   526,   527,   528,
     529,   530,   531,   533,   534,   535,   536,   538,   539,   540,
     541,   542,   543,   544,   546,   551,   552,   553,   554,   555,
     556,   557,   558,   562,   563,   565,   566,   567,   569,   570,
     571,   575,   576,   587,   588,   589,   590,   591,   592,   598,
     599,   600,   603,   604,   605,   625,   626,   627,   629,   630,
     631,   632,   633,   635,   641,   644,   658,   661,   665,   669,
     670,   682,   724,   725,   726,   732,   733,   734,   735,   738,
     739,   740,   741,   742,   743,   745,   746,   753,   754,   755,
     756,   757,   767,   774,   789,   790,   791,   792,   793,   796,
     797,   869,   930,   931,   932,   933,   934,   935,  1011,  1012,
    1013,  1014,  1015,  1021,  1023,  1028,  1034,  1035,  1036,  1037,
    1039,  1040,  1058,  1059,  1060,  1061,  1077,  1078,  1079,  1080,
    1083,  1085,  1086,  1094,  1095,   348,   348,   348,   398,   452,
     471,   402,   418,   449,   417,   495,   419,   458,   459,   460,
     472,   498,   419,   458,   420,   467,     5,     6,    10,    11,
      12,    17,    18,    22,    25,    28,    34,    37,    38,    41,
      52,    53,   397,   403,   404,   405,   406,   407,   408,   418,
     419,   425,   426,   428,   429,   430,   431,   432,   433,   434,
     435,   436,   437,   438,   439,   440,   441,   442,   444,   446,
     483,   484,   485,   486,   487,   490,   491,   492,   493,   496,
     497,   508,   446,   485,   398,   473,   474,   496,   400,   428,
     441,   445,   496,   472,   475,   476,   477,   478,   402,   419,
     417,   465,    87,    88,   213,   213,   393,   375,   130,   169,
     361,   373,   135,   168,   217,   234,   235,   242,   247,   256,
     261,   284,   296,   310,   314,   361,   361,   388,   204,   266,
     568,   357,   132,   135,   141,   168,   190,   206,   217,   218,
     219,   234,   241,   242,   243,   247,   250,   252,   256,   277,
     284,   296,   314,   361,   610,   611,   727,   736,   361,   102,
     107,   108,   111,   112,   118,   119,   121,   122,   124,   126,
     132,   139,   141,   142,   151,   153,   160,   162,   163,   184,
     185,   186,   187,   189,   191,   193,   194,   195,   197,   200,
     205,   212,   215,   219,   220,   221,   222,   229,   234,   238,
     241,   244,   248,   249,   250,   251,   254,   257,   268,   269,
     270,   271,   281,   290,   292,   298,   299,   312,   313,   316,
     317,   325,   337,   342,   344,   352,   355,   356,   357,   358,
     359,   360,   361,   367,   369,   377,   381,   559,   561,   896,
     898,   899,   900,   901,   902,   903,   906,   913,   927,   949,
    1096,  1098,   354,   798,   341,   802,   804,   805,   898,  1096,
     135,   141,   168,   217,   218,   219,   234,   241,   242,   247,
     250,   256,   261,   277,   284,   296,   310,   314,   361,   736,
     116,   233,   179,   114,   361,   378,   545,   166,   215,   362,
     374,   381,   382,   387,   395,   522,   523,   356,   357,   361,
     103,   104,   131,   138,   145,   157,   170,   177,   220,   223,
     233,   255,   267,   284,   306,   593,   594,  1096,   798,   798,
     798,   361,   159,   199,   252,   280,   873,   874,   875,   876,
     877,   896,   898,   593,   568,  1096,   798,   102,   361,  1096,
     159,   798,   794,   795,  1096,   573,  1096,   242,   242,   242,
     242,   242,   242,   792,   164,   372,   202,   204,   202,   204,
     372,   386,   270,   357,   361,   348,   361,   789,   348,   104,
     125,   131,   164,   230,   357,   552,   553,   556,   357,   552,
     553,   272,   348,   348,   745,   746,   753,   556,   157,   376,
     388,   388,   573,   162,   187,   761,   164,   863,   178,   207,
     251,   285,   781,   860,   792,   348,   348,   348,   573,   573,
     573,   573,  1096,   450,   420,   442,   481,    81,   453,   419,
     459,   416,   461,   463,   467,   453,   419,   418,   445,   418,
     416,   483,   397,   496,   418,   444,   397,   428,   397,   397,
     397,   497,   397,   428,   428,   444,   472,   478,    52,    53,
      54,   397,   399,   401,    42,    43,    44,    45,    46,    47,
      48,    49,    50,    51,   417,   443,   430,   404,   409,   410,
     405,   406,    58,    59,    61,    62,   411,   412,    56,    57,
     403,   413,   414,    55,    60,   415,   402,   418,   419,   486,
     416,   398,   402,   400,   397,   399,   467,   471,   479,   480,
     398,   402,   466,   445,   419,   111,   348,   350,   130,   169,
     361,   373,   361,   130,   361,   368,   108,   112,   114,   131,
     152,   197,   222,   289,   318,  1024,  1096,   573,   573,   573,
     121,   236,   573,   573,  1096,   573,   573,   261,  1096,  1096,
     107,   236,   361,   361,   123,   242,   361,   283,   314,   276,
    1096,   252,   290,   241,   573,   573,   573,   573,   314,   284,
    1096,  1096,   261,  1096,   361,   310,   261,   135,   240,   364,
     380,   391,   513,   262,   898,   911,   912,   337,   903,   119,
     559,   904,  1096,   345,   265,   783,   873,   926,   903,   903,
     174,   208,   379,  1108,  1109,  1110,   357,   357,   353,   905,
     337,   336,   333,   342,   344,   341,   346,   337,   339,   345,
     166,   799,   179,  1100,   343,   109,   358,   806,  1096,   345,
     276,  1096,  1096,   573,   573,   241,   573,   573,   573,   573,
     573,   573,  1096,   573,  1096,   573,   261,  1096,  1096,   361,
     135,   260,   361,   573,   257,   357,   947,  1016,  1017,  1019,
    1020,  1096,  1105,   342,   344,   356,   524,   524,   361,   166,
    1098,   216,   106,   235,   256,   314,   361,   106,   217,   218,
     234,   235,   241,   242,   247,   256,   261,   277,   296,   314,
     106,   106,   218,   256,   314,   106,   106,   106,   106,   106,
     106,   204,   246,   343,   103,   179,   179,   179,   257,   357,
     877,   337,   927,   927,   206,   105,   336,   175,   180,   188,
     199,   279,   335,   349,   350,   351,   878,   879,   880,   881,
     882,   883,   884,   885,   886,   887,   888,   889,   890,   891,
     892,   893,   894,   895,   166,   204,   246,   361,   103,   144,
     801,   350,   181,   220,   572,   350,   337,   573,   744,   343,
     337,   728,   246,   345,   573,   573,  1096,   573,  1096,  1096,
     338,   356,   357,   357,   361,   357,   361,   361,   357,  1099,
     343,   166,   164,   516,   516,   235,   568,   206,   568,   348,
     361,   270,   204,   293,   361,   864,   255,   265,   731,   115,
     361,   103,   796,   189,   861,   860,   337,   937,   937,   109,
     180,   936,   101,   113,  1062,  1064,   109,   481,   482,   453,
     445,   402,   418,   462,   416,   453,   416,   483,   508,    34,
     418,   444,   418,   418,   478,   444,   444,   444,   398,   397,
     471,   398,   496,   398,   427,   442,   444,   496,   442,   430,
     430,   430,   431,   431,   432,   432,   433,   433,   433,   433,
     434,   434,   435,   436,   437,   438,   439,   440,   442,   483,
     508,    35,   496,   398,   475,   479,   400,   445,   480,   397,
     399,    35,   477,   361,   160,   248,   361,   130,   361,   368,
     337,   135,   191,   314,   361,   361,   361,   135,   361,   239,
     361,   235,   361,  1032,  1033,   126,   126,   134,   142,   151,
     198,   239,   361,   642,   643,   657,   668,   135,   310,   361,
     365,   100,   103,   104,   122,   142,   145,   151,   193,   238,
     281,   289,   307,   315,   361,   646,   126,   142,   151,  1076,
     137,   142,   151,   243,   281,   283,   579,   580,   581,   582,
     583,   584,   585,   126,   221,   236,   289,   361,   662,   663,
     573,   100,   145,   163,   236,   239,   361,   104,   105,   114,
     145,   152,   289,   308,   309,  1038,  1053,   361,   361,   236,
     281,   361,   574,  1096,   573,   135,   115,  1096,  1096,   361,
    1022,   284,   141,   168,   217,   247,   250,   361,   727,   573,
     337,   642,   666,   164,   177,   211,   220,   307,   314,   337,
     683,   685,   690,   691,   722,  1114,  1096,   283,   573,   361,
     156,   157,  1018,  1096,   573,   276,   390,   514,   873,   262,
     907,   908,   149,   910,   912,   873,   345,   559,  1096,   785,
     786,  1096,   233,   788,   928,   929,   338,   343,   208,  1108,
    1108,   357,   385,  1106,  1107,  1106,   338,   926,   312,   900,
     901,   901,   902,   902,   103,   144,   338,   341,   926,   873,
     945,   138,   215,   280,   374,   381,   382,   559,   560,  1096,
     744,   357,   367,   369,  1101,   166,   758,   805,   358,   559,
     341,  1096,  1096,   573,   117,   640,   117,   660,   573,   361,
    1057,   276,   164,   164,   337,   714,   147,   357,   367,   369,
     537,  1097,  1108,   348,   348,   119,   913,   946,  1096,   337,
     345,   347,   356,   356,   179,   257,   217,   234,   242,   247,
     284,   296,   361,   141,   217,   234,   242,   247,   261,   284,
     296,   361,   241,   261,   242,   141,   217,   234,   241,   242,
     247,   261,   277,   284,   296,   361,   241,   217,   216,   277,
     242,   234,   242,   242,   242,   141,   573,   218,   595,   596,
    1096,   594,   179,   747,   748,   744,   573,   573,   537,  1097,
     875,   876,   361,   375,   199,   200,   898,   175,   188,   279,
     898,   350,   103,   106,   237,   350,   351,   103,   106,   237,
     103,   106,   237,   350,   898,   898,   898,   898,   898,   898,
     200,   328,   329,   337,   355,   356,   358,   359,   559,   838,
     897,   927,  1096,  1098,   897,   897,   897,   897,   897,   897,
     897,   897,   897,   897,   897,   595,   141,   573,   232,   135,
     802,   142,   151,   186,   267,   384,  1096,   265,   337,   778,
     779,   780,   782,   784,   787,   788,   211,  1118,   806,   795,
     559,   729,   730,   109,  1096,  1096,   246,   174,   345,   337,
     211,   636,   265,   532,   532,   343,   357,   220,   255,   236,
     290,   257,  1099,   573,   356,   864,   220,   865,   866,   898,
     115,   356,   357,   559,   862,   861,   338,   938,   939,  1096,
     227,   936,   249,   956,   960,   965,   204,   138,   177,   255,
    1063,   358,   402,   419,   463,   445,   483,   508,   397,   418,
     444,   418,   398,   398,   398,   398,   430,   398,   402,   400,
     416,   398,   398,   400,   398,   475,   400,   445,   348,   338,
     338,   337,   246,   246,  1096,   358,   254,  1029,   358,   361,
     121,   125,   158,   230,   361,   378,   265,   115,   344,   356,
     643,   361,   276,   350,   350,   361,   572,   350,   123,   128,
     211,   656,   659,   699,   700,   284,   211,   314,   659,   211,
     231,   128,   190,   211,   214,   252,   659,   231,   212,   211,
     211,  1114,   123,   128,   211,   246,   356,   211,   211,   645,
     314,   361,   361,   314,  1096,   115,   585,   211,   361,   663,
     246,   202,   204,   350,   664,   361,  1084,   242,   361,   242,
     361,   103,   293,   619,   268,   286,   309,   361,   111,   265,
     361,   624,   242,   268,   361,   384,   620,   621,   361,   361,
     112,   361,   112,   361,   239,   361,   564,   350,   124,   142,
     151,   152,   239,   361,  1018,  1089,  1091,  1093,   361,   180,
     345,   180,   276,   357,   361,   127,   257,   737,   350,  1024,
     361,   261,   164,   356,   559,   702,   703,   667,   668,   573,
     361,   115,   267,   361,   384,   356,  1096,   697,   698,   699,
     703,   270,   692,   693,   694,   142,   151,   684,   691,   690,
     361,   115,   728,   358,  1041,  1042,  1019,   164,   615,   728,
    1096,   133,   245,   909,   898,   908,   910,   898,   152,   109,
     559,  1096,   343,   728,   798,   781,   861,   873,  1108,  1109,
     357,  1109,   338,   341,   926,   926,   210,   917,   338,   338,
     340,   905,   337,   339,   345,   806,  1108,   357,   357,   343,
     759,   760,  1096,   263,   872,   345,   129,   361,  1096,   361,
     361,   559,   718,   258,  1098,  1108,   357,   357,   343,   152,
     152,   345,   338,   926,   947,  1096,   350,  1101,   147,   261,
     261,   261,  1096,   246,   343,   744,   748,   778,   137,   337,
     714,   778,  1118,  1118,   200,   154,   898,   898,   105,   103,
     106,   237,   103,   106,   237,   103,   106,   237,   103,   106,
     237,   926,   345,  1096,   166,  1096,   276,   179,  1102,   220,
     361,   785,   782,   338,   781,   860,   782,   337,   236,   338,
     343,   337,   113,   231,   361,   870,  1096,   211,   634,   115,
     684,   361,   357,   384,   201,   293,   361,   517,   361,  1097,
     337,   384,   343,   110,   140,   867,   865,   343,   338,   343,
     174,   208,   940,   559,   952,   953,  1096,   133,   955,   957,
     958,   959,   961,   962,   963,   965,  1096,  1096,   941,  1096,
     152,   965,   573,   201,  1065,   206,   419,   481,   444,   398,
     444,   418,   418,   444,   483,   483,   483,   442,   441,   398,
     400,   358,   358,   246,   109,  1031,   361,   257,  1030,   246,
     356,   356,   356,   344,   356,   344,   356,   356,   242,   103,
    1096,   137,   160,   248,   361,   356,   358,   361,   350,   160,
     248,  1096,  1096,   284,   653,   337,   120,   165,   190,   214,
     252,   657,  1096,  1096,   270,   337,   195,  1096,   252,  1096,
     183,   337,   559,   195,  1096,  1096,  1096,   559,  1096,  1096,
    1096,  1096,  1096,  1096,  1096,   202,   204,   586,  1096,  1096,
     573,   202,   204,   204,   361,  1082,   166,   345,   618,   358,
     613,   614,   618,   613,   293,   356,   356,   361,   610,   142,
     151,   613,   657,   361,   309,   622,   623,  1096,   356,   268,
     621,   358,  1041,   358,  1055,  1056,  1055,   344,   356,   358,
     361,   358,   898,   898,   356,  1019,   358,  1096,   358,   205,
     257,   356,   246,  1096,   257,   356,  1051,   361,  1025,  1026,
    1027,   573,   573,   259,   305,   704,   710,   711,  1096,   338,
     343,   189,  1096,   338,   343,   271,   337,   109,   694,   231,
     231,   690,  1041,  1096,   683,   361,  1043,  1044,   292,   304,
     343,  1046,  1047,  1049,  1050,   239,   361,   109,   616,   109,
     257,   737,   265,   515,   898,   909,   152,   711,   345,   786,
     109,   801,   929,   338,   338,   338,   338,   337,   917,   278,
     914,   345,   338,   926,   945,   559,   560,  1096,   872,  1106,
    1106,   357,   367,   369,   345,   873,   341,   105,   117,   601,
     179,   179,   338,   343,   337,  1106,  1106,   357,   367,   369,
     348,   348,   381,  1096,   338,  1098,   246,   595,   596,   337,
     773,   258,   718,   258,   806,   714,   898,   154,   105,   898,
     338,   559,  1096,   166,   595,   357,   361,   367,   369,  1103,
    1104,   166,   807,   361,   220,   338,   787,   861,   860,  1096,
     337,   559,   762,   763,   764,  1096,   730,   790,   145,   361,
     231,   255,   286,   174,  1096,   338,  1096,   639,  1114,   356,
     518,  1096,   356,   350,   716,   873,   866,   299,   868,   862,
     939,   208,   952,   336,   936,   337,   345,  1096,   941,   114,
     959,   155,   282,   964,   180,   224,  1066,   718,   138,   177,
     255,   398,   483,   398,   398,   444,   398,   444,   418,    36,
     358,   358,   358,   112,   358,   356,   356,   202,   204,   356,
     384,   314,  1111,  1112,   337,   699,   701,   702,   873,   183,
     252,   183,   337,   715,   314,   284,   650,   271,   337,   559,
     337,   660,   559,   717,   343,   111,   258,  1114,   246,   246,
     246,   125,   361,  1082,  1096,   343,   614,   356,   265,   337,
     343,   345,   356,   308,   309,   361,  1044,  1054,   343,   246,
     356,   361,   345,   357,   357,   361,  1043,  1096,  1096,   361,
     236,   361,   361,  1027,   361,  1026,   728,   174,   705,   704,
     361,   712,   713,   337,   722,   723,   703,   356,   337,   683,
     698,   109,   718,   778,   195,   195,  1048,  1049,   577,   578,
     580,   583,   584,   585,   692,   202,   204,   356,   361,  1043,
     361,   356,  1052,  1042,  1047,   898,   361,   361,   606,   778,
    1096,   257,   227,   377,   164,   338,   559,   337,   802,   917,
     917,   917,   211,   918,   171,   917,   559,   338,   340,   905,
     337,   345,   861,  1109,  1109,  1108,   357,   357,  1096,   361,
     129,  1098,  1098,   559,   137,   749,   750,   898,  1109,  1109,
    1108,   357,   357,   345,   595,   265,   597,   764,   772,   258,
     338,   337,   751,   752,   257,   166,   898,   898,   345,   595,
     601,  1103,  1103,  1108,   343,   242,   319,   320,   337,   808,
     809,   839,   842,  1096,   872,   861,   338,   559,   765,   766,
    1096,   343,   872,   350,   345,   338,   289,   628,   361,   864,
     870,   246,   337,   692,   343,   338,   343,   867,   374,   381,
     137,   347,   942,   249,   291,   955,   356,   559,  1096,   937,
     104,   114,   118,   121,   125,   130,   136,   158,   161,   164,
     169,   173,   192,   200,   205,   227,   230,   236,   264,   288,
     349,   565,   566,   567,   569,   745,   746,   753,   754,   767,
     774,   778,   947,   949,   950,   954,   977,   978,   979,   980,
     981,   982,   983,   984,   988,   995,   996,   997,   998,   999,
    1001,  1002,  1003,  1005,  1006,  1007,  1008,  1009,  1010,  1096,
     348,   952,   242,   361,   196,   203,  1067,  1068,  1069,   164,
    1073,  1065,   418,   483,   483,   398,   483,   398,   398,   444,
     483,   191,  1096,   692,   654,   655,  1096,   338,   338,   337,
     715,   867,   715,   717,   236,   672,  1096,   337,   270,   647,
     109,   718,   145,   199,   200,   236,   717,   867,   338,   343,
    1096,   337,   337,   559,  1096,  1096,   345,   356,   358,   609,
     356,   623,  1096,  1052,  1056,  1055,  1096,   205,   343,  1043,
     283,  1096,   236,   109,   231,   338,   705,   257,   356,   718,
     692,   337,   338,   578,   361,  1081,   361,   382,   361,  1043,
     361,   361,   152,  1087,   268,   309,   361,   607,   608,   265,
     731,  1096,   265,   779,   179,   803,  1100,   115,   207,   921,
     337,   345,   338,   926,   559,  1106,  1106,   601,   338,   343,
    1106,  1106,  1096,   597,   170,   338,   343,   337,   778,   749,
     343,   809,   573,   559,   601,   361,   602,  1106,  1106,   367,
     369,  1103,   337,   337,   337,   778,   343,   167,   176,   184,
     229,   843,   332,   337,   345,  1118,   127,   239,   297,   855,
     856,   858,   338,   343,   345,   763,   861,   137,   898,   559,
     246,   254,   871,   286,   242,   718,  1096,   190,   673,   674,
     873,   945,   350,   941,   338,   343,   336,   345,   180,   235,
     977,   262,   898,   943,   989,   990,  1096,   568,   348,   957,
     941,  1096,   951,  1096,  1096,   873,   944,   977,   348,   947,
    1096,   348,   945,   568,   950,  1096,   944,   348,   976,  1096,
     349,   348,   348,   348,   348,   348,   348,   348,   348,   348,
     348,   863,   347,   155,   970,   971,   978,   348,   941,   345,
     942,   201,   337,   343,   231,   242,  1070,   148,   936,  1075,
     483,   483,   483,   398,  1113,  1114,   338,   343,   211,   692,
     718,   672,   672,   672,   338,   361,   257,   678,   650,   651,
     652,  1096,   337,   337,   338,   137,   200,   338,   137,   338,
     660,   559,   179,   688,   689,   898,   688,  1096,   343,   338,
     211,   357,   357,   115,  1096,   778,   356,   723,   137,   709,
     358,   338,   343,   338,   109,   314,   361,   695,   696,   271,
     361,  1082,   109,   361,  1052,   356,  1052,   361,  1043,   898,
    1088,  1089,   356,   609,   608,   361,   612,   613,   227,   338,
     948,   950,   807,   807,   898,   919,   920,   115,   361,   922,
     207,   559,   338,   905,  1109,  1109,   750,  1109,  1109,   385,
     764,   749,   338,   752,   204,   337,   775,   602,  1109,  1109,
    1103,  1103,  1108,   302,   361,   810,   913,  1096,  1096,   778,
     338,   809,   209,   844,   844,   844,   182,  1096,   840,   841,
    1096,  1096,   294,   295,   811,   812,   819,   115,   265,   873,
     171,   800,   858,   361,   859,   350,   766,  1096,  1096,   382,
     864,  1096,   338,   337,   361,   671,   867,   945,   342,   344,
     356,   249,   291,   559,  1096,   778,   236,   970,   944,   262,
     991,   992,   149,   994,   989,   345,   348,   114,   262,  1004,
     179,   345,   174,   175,  1119,   348,   245,   987,   152,   348,
     345,   348,   350,   345,   996,   348,   345,  1096,   348,   350,
     262,   972,   973,   974,   152,   348,   559,   947,  1096,   348,
     953,   966,  1096,   559,   968,   969,  1068,   109,  1071,   231,
     240,   955,   483,   655,  1096,   337,  1115,   338,   678,   678,
     678,   350,   284,   647,   338,   343,   314,   559,   648,   649,
     695,   271,   338,   338,   898,   660,   867,   656,   338,   343,
     338,   211,   246,   358,  1096,   205,  1096,   731,   898,   700,
     706,   707,   708,   342,   344,   356,   337,   778,  1096,   338,
     696,   109,   361,  1082,   779,   361,  1045,  1043,  1090,  1091,
     617,   618,   343,   872,   872,   343,   865,   275,   279,   356,
     361,   923,   925,   338,   115,   338,   873,   137,   776,   777,
     898,   872,  1106,  1106,   337,   338,   345,   343,   338,   811,
     809,   806,   338,   343,   345,  1118,  1118,   337,   361,   820,
     806,   873,   873,   115,   172,   854,   859,   192,   856,   857,
     898,   361,   871,   343,   337,   211,   675,   676,   180,   672,
     356,   356,   338,   336,   863,   361,   152,   987,   943,   993,
     994,   991,   977,   152,  1096,   977,   944,   348,   948,  1096,
     311,   943,   947,  1096,   977,   149,   150,   303,   985,   986,
     192,   947,   945,  1096,   941,  1096,   351,   945,   287,   975,
     976,   974,   345,   284,   967,   345,   711,   338,   343,  1072,
    1096,   262,  1074,   314,   211,  1116,  1117,   223,   719,   202,
     204,   268,   269,   314,   679,   680,   681,   652,  1096,   314,
     338,   343,   338,   109,   338,   653,   179,   689,   179,  1096,
    1096,   357,   120,   190,   199,   200,   214,   252,   719,   708,
     356,   356,   338,   211,   686,   687,   337,   361,  1082,   361,
    1045,  1052,  1092,  1093,   343,   950,   855,   855,   920,   923,
     273,   356,   273,   274,   898,   915,   916,   262,   768,   769,
     338,   343,   861,  1109,  1109,   926,   806,   559,  1096,   358,
     806,   806,   204,   806,   841,  1096,   811,   361,   813,   814,
     299,   337,   370,   389,   396,   845,   848,   852,   853,   898,
     873,   634,   242,   637,   638,  1096,   338,   343,   361,   679,
     338,   338,   249,   348,   941,   987,   152,   118,   348,   970,
     348,   179,   943,   334,   996,   337,   977,   944,   944,   152,
     348,   348,   348,   351,   348,   987,   987,   206,   559,   115,
     348,  1096,   348,   969,   337,  1096,  1096,   338,   343,   573,
     356,  1096,   681,  1096,   649,  1115,   337,   337,   337,   246,
     345,   873,   252,   200,   183,   867,   338,   338,  1096,   338,
     343,   695,  1082,   361,   618,   800,   800,   105,   361,   110,
     140,   338,   343,   199,   361,   770,   769,   777,   338,   345,
     338,   873,  1118,   806,   337,   164,   343,   815,   337,   559,
     821,   823,   337,   337,   337,   343,  1096,   338,   343,   204,
     676,   348,   118,   348,   152,   948,   334,   943,   941,   338,
     926,   987,   987,   173,   976,   711,   345,   873,   693,  1117,
     714,   695,   656,   656,  1096,  1096,   338,   867,   867,   672,
     258,  1112,   687,   338,   854,   854,   275,   361,   924,   925,
     916,   361,   361,   245,   559,  1096,   806,   341,   898,   337,
     559,   814,   175,   816,   822,   823,   164,   846,   847,   898,
     846,   337,   845,   849,   850,   851,   898,   853,   246,   638,
    1096,   348,   941,   348,   943,   313,  1000,   348,   338,   985,
     985,   348,  1096,   338,   204,   720,   338,   653,   653,   345,
     672,   672,   678,   137,   185,   337,   274,   273,   274,   177,
     255,   771,   338,   338,   559,   337,   338,   338,   343,   821,
     338,   343,   338,   338,   338,   343,   211,   314,   677,   348,
    1000,   943,   996,   138,   177,   255,  1115,   343,   343,  1096,
     678,   678,  1112,   244,   688,   773,   236,   806,   806,   338,
     342,   344,   817,   818,   837,   838,   823,   175,   824,   847,
     850,   851,  1096,  1096,   996,   941,   117,   226,   361,   721,
     721,   721,   656,   656,   211,   337,   338,   258,   762,   838,
     838,   338,   343,   806,   337,   338,   258,   941,   348,   361,
     653,   653,  1096,   688,  1112,   337,   861,   818,   337,   559,
     825,   826,   827,   829,   137,   185,   337,   348,   338,   338,
     338,   749,   828,   829,   338,   343,   109,   244,   688,  1112,
     338,   338,   343,   826,   337,   830,   832,   833,   834,   835,
     836,   837,   337,   338,   829,   831,   832,   333,   342,   344,
     341,   346,   688,   338,   343,   835,   836,   836,   837,   837,
     338,   832
};

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		(-2)
#define YYEOF		0

#define YYACCEPT	goto yyacceptlab
#define YYABORT		goto yyabortlab
#define YYERROR		goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL		goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yytoken = YYTRANSLATE (yychar);				\
      YYPOPSTACK (1);						\
      goto yybackup;						\
    }								\
  else								\
    {								\
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;							\
    }								\
while (YYID (0))


#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)				\
    do									\
      if (YYID (N))                                                    \
	{								\
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;	\
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;	\
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;		\
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;	\
	}								\
      else								\
	{								\
	  (Current).first_line   = (Current).last_line   =		\
	    YYRHSLOC (Rhs, 0).last_line;				\
	  (Current).first_column = (Current).last_column =		\
	    YYRHSLOC (Rhs, 0).last_column;				\
	}								\
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)			\
     fprintf (File, "%d.%d-%d.%d",			\
	      (Loc).first_line, (Loc).first_column,	\
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)			  \
do {									  \
  if (yydebug)								  \
    {									  \
      YYFPRINTF (stderr, "%s ", Title);					  \
      yy_symbol_print (stderr,						  \
		  Type, Value); \
      YYFPRINTF (stderr, "\n");						  \
    }									  \
} while (YYID (0))


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_value_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# else
  YYUSE (yyoutput);
# endif
  switch (yytype)
    {
      default:
	break;
    }
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
yy_symbol_print (yyoutput, yytype, yyvaluep)
    FILE *yyoutput;
    int yytype;
    YYSTYPE const * const yyvaluep;
#endif
{
  if (yytype < YYNTOKENS)
    YYFPRINTF (yyoutput, "token %s (", yytname[yytype]);
  else
    YYFPRINTF (yyoutput, "nterm %s (", yytname[yytype]);

  yy_symbol_value_print (yyoutput, yytype, yyvaluep);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
#else
static void
yy_stack_print (yybottom, yytop)
    yytype_int16 *yybottom;
    yytype_int16 *yytop;
#endif
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)				\
do {								\
  if (yydebug)							\
    yy_stack_print ((Bottom), (Top));				\
} while (YYID (0))


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print (YYSTYPE *yyvsp, int yyrule)
#else
static void
yy_reduce_print (yyvsp, yyrule)
    YYSTYPE *yyvsp;
    int yyrule;
#endif
{
  int yynrhs = yyr2[yyrule];
  int yyi;
  unsigned long int yylno = yyrline[yyrule];
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
	     yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr, yyrhs[yyprhs[yyrule] + yyi],
		       &(yyvsp[(yyi + 1) - (yynrhs)])
		       		       );
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)		\
do {					\
  if (yydebug)				\
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen (const char *yystr)
#else
static YYSIZE_T
yystrlen (yystr)
    const char *yystr;
#endif
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy (char *yydest, const char *yysrc)
#else
static char *
yystpcpy (yydest, yysrc)
    char *yydest;
    const char *yysrc;
#endif
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
	switch (*++yyp)
	  {
	  case '\'':
	  case ',':
	    goto do_not_strip_quotes;

	  case '\\':
	    if (*++yyp != '\\')
	      goto do_not_strip_quotes;
	    /* Fall through.  */
	  default:
	    if (yyres)
	      yyres[yyn] = *yyp;
	    yyn++;
	    break;

	  case '"':
	    if (yyres)
	      yyres[yyn] = '\0';
	    return yyn;
	  }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
   YYCHAR while in state YYSTATE.  Return the number of bytes copied,
   including the terminating null byte.  If YYRESULT is null, do not
   copy anything; just return the number of bytes that would be
   copied.  As a special case, return 0 if an ordinary "syntax error"
   message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
   size calculation.  */
static YYSIZE_T
yysyntax_error (char *yyresult, int yystate, int yychar)
{
  int yyn = yypact[yystate];

  if (! (YYPACT_NINF < yyn && yyn <= YYLAST))
    return 0;
  else
    {
      int yytype = YYTRANSLATE (yychar);
      YYSIZE_T yysize0 = yytnamerr (0, yytname[yytype]);
      YYSIZE_T yysize = yysize0;
      YYSIZE_T yysize1;
      int yysize_overflow = 0;
      enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
      char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
      int yyx;

# if 0
      /* This is so xgettext sees the translatable formats that are
	 constructed on the fly.  */
      YY_("syntax error, unexpected %s");
      YY_("syntax error, unexpected %s, expecting %s");
      YY_("syntax error, unexpected %s, expecting %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s");
      YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
      char *yyfmt;
      char const *yyf;
      static char const yyunexpected[] = "syntax error, unexpected %s";
      static char const yyexpecting[] = ", expecting %s";
      static char const yyor[] = " or %s";
      char yyformat[sizeof yyunexpected
		    + sizeof yyexpecting - 1
		    + ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		       * (sizeof yyor - 1))];
      char const *yyprefix = yyexpecting;

      /* Start YYX at -YYN if negative to avoid negative indexes in
	 YYCHECK.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;

      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yycount = 1;

      yyarg[0] = yytname[yytype];
      yyfmt = yystpcpy (yyformat, yyunexpected);

      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
	if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR)
	  {
	    if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
	      {
		yycount = 1;
		yysize = yysize0;
		yyformat[sizeof yyunexpected - 1] = '\0';
		break;
	      }
	    yyarg[yycount++] = yytname[yyx];
	    yysize1 = yysize + yytnamerr (0, yytname[yyx]);
	    yysize_overflow |= (yysize1 < yysize);
	    yysize = yysize1;
	    yyfmt = yystpcpy (yyfmt, yyprefix);
	    yyprefix = yyor;
	  }

      yyf = YY_(yyformat);
      yysize1 = yysize + yystrlen (yyf);
      yysize_overflow |= (yysize1 < yysize);
      yysize = yysize1;

      if (yysize_overflow)
	return YYSIZE_MAXIMUM;

      if (yyresult)
	{
	  /* Avoid sprintf, as that infringes on the user's name space.
	     Don't have undefined behavior even if the translation
	     produced a string with the wrong number of "%s"s.  */
	  char *yyp = yyresult;
	  int yyi = 0;
	  while ((*yyp = *yyf) != '\0')
	    {
	      if (*yyp == '%' && yyf[1] == 's' && yyi < yycount)
		{
		  yyp += yytnamerr (yyp, yyarg[yyi++]);
		  yyf += 2;
		}
	      else
		{
		  yyp++;
		  yyf++;
		}
	    }
	}
      return yysize;
    }
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
yydestruct (yymsg, yytype, yyvaluep)
    const char *yymsg;
    int yytype;
    YYSTYPE *yyvaluep;
#endif
{
  YYUSE (yyvaluep);

  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  switch (yytype)
    {

      default:
	break;
    }
}

/* Prevent warnings from -Wmissing-prototypes.  */
#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse (void *YYPARSE_PARAM);
#else
int yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse (void);
#else
int yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */





/*-------------------------.
| yyparse or yypush_parse.  |
`-------------------------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void *YYPARSE_PARAM)
#else
int
yyparse (YYPARSE_PARAM)
    void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
     || defined __cplusplus || defined _MSC_VER)
int
yyparse (void)
#else
int
yyparse ()

#endif
#endif
{
/* The lookahead symbol.  */
int yychar;

/* The semantic value of the lookahead symbol.  */
YYSTYPE yylval;

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       `yyss': related to states.
       `yyvs': related to semantic values.

       Refer to the stacks thru separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yytoken = 0;
  yyss = yyssa;
  yyvs = yyvsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */
  yyssp = yyss;
  yyvsp = yyvs;

/* User initialization code.  */

/* Line 1242 of yacc.c  */
#line 12 "ulpCompy.y"
{
    idlOS::memset(&yyval, 0, sizeof(yyval));

    /* BUG-28061 : preprocessing을마치면 marco table을 초기화하고, *
     *             ulpComp 에서 재구축한다.                       */
    switch ( gUlpProgOption.mOptParseInfo )
    {
        // 옵션 -parse none 에 해당하는 상태.
        case PARSE_NONE :
            gUlpCOMPStartCond = CP_ST_NONE;
            break;
        // 옵션 -parse partial 에 해당하는 상태.
        case PARSE_PARTIAL :
            gUlpCOMPStartCond = CP_ST_PARTIAL;
            break;
        // 옵션 -parse full 에 해당하는 상태.
        case PARSE_FULL :
            gUlpCOMPStartCond = CP_ST_C;
            break;
        default :
            break;
    }
}

/* Line 1242 of yacc.c  */
#line 7772 "ulpCompy.cpp"

  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack.  Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	yytype_int16 *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  This used to be a
	   conditional around just the two extra args, but that might
	   be undefined if yyoverflow is a macro.  */
	yyoverflow (YY_("memory exhausted"),
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);

	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
	goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
	yystacksize = YYMAXDEPTH;

      {
	yytype_int16 *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyexhaustedlab;
	YYSTACK_RELOCATE (yyss_alloc, yyss);
	YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yyn == YYPACT_NINF)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yyn == 0 || yyn == YYTABLE_NINF)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  *++yyvsp = yylval;

  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 7:

/* Line 1455 of yacc.c  */
#line 543 "ulpCompy.y"
    {
        YYACCEPT;
    ;}
    break;

  case 84:

/* Line 1455 of yacc.c  */
#line 699 "ulpCompy.y"
    {
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
         * 2th. problem : 빈구조체 선언이 허용안됨. ex) struct A; */
        // <type> ; 이 올수 있다. ex> int; char; struct A; ...
        gUlpParseInfo.ulpInitHostInfo();
    ;}
    break;

  case 85:

/* Line 1455 of yacc.c  */
#line 706 "ulpCompy.y"
    {
        iduListNode *sIterator = NULL;
        iduListNode *sNextNode = NULL;
        ulpSymTElement *sSymNode;

        if( gUlpParseInfo.mFuncDecl == ID_TRUE )
        {
            gUlpScopeT.ulpSDelScope( gUlpCurDepth + 1 );
        }

        /* BUG-35518 Shared pointer should be supported in APRE */
        /* convert the sentence for shared pointer */
        if ( gUlpParseInfo.mIsSharedPtr == ID_TRUE)
        {
            WRITESTR2BUFCOMP ( (SChar *)" */\n" );
            IDU_LIST_ITERATE_SAFE(&(gUlpParseInfo.mSharedPtrVarList),
                                  sIterator, sNextNode )
            {
                sSymNode = (ulpSymTElement *)sIterator->mObj;
                if ( gDontPrint2file != ID_TRUE )
                {
                    gUlpCodeGen.ulpGenSharedPtr( sSymNode );
                }
                IDU_LIST_REMOVE(sIterator);
                idlOS::free(sIterator);
            }
            IDU_LIST_INIT( &(gUlpParseInfo.mSharedPtrVarList) );
        }

        // varchar 선언의 경우 해당 code를 주석처리 한후,
        // struct { char arr[...]; SQLLEN len; } 으로의 변환이 필요함.
        if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) ||
             (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_NVARCHAR) )
        {
            if ( gUlpParseInfo.mFuncDecl != ID_TRUE )
            {
                WRITESTR2BUFCOMP ( (SChar *)" */\n" );

                /* BUG-26375 valgrind bug */
                IDU_LIST_ITERATE_SAFE(&(gUlpParseInfo.mVarcharVarList),
                                      sIterator, sNextNode )
                {
                    sSymNode = (ulpSymTElement *)sIterator->mObj;
                    if ( gDontPrint2file != ID_TRUE )
                    {
                        gUlpCodeGen.ulpGenVarchar( sSymNode );
                    }
                    IDU_LIST_REMOVE(sIterator);
                    idlOS::free(sIterator);
                }
                IDU_LIST_INIT( &(gUlpParseInfo.mVarcharVarList) );
                gUlpParseInfo.mVarcharDecl = ID_FALSE;
            }
        }
   


        gUlpParseInfo.mFuncDecl = ID_FALSE;
        gUlpParseInfo.mHostValInfo4Typedef = NULL;
        // 하나의 선언구문이 처리되면 따로 저장하고 있던 호스트변수정보를 초기화함.
        gUlpParseInfo.ulpInitHostInfo();
    ;}
    break;

  case 90:

/* Line 1455 of yacc.c  */
#line 779 "ulpCompy.y"
    {
        SChar *sVarName;
        ulpSymTNode *sSymNode;
        iduListNode *sIterator = NULL;
        iduListNode *sVarcharListNode = NULL;
        /* BUG-35518 Shared pointer should be supported in APRE */
        iduListNode *sSharedPtrVarListNode = NULL;

        if( gUlpParseInfo.mFuncDecl != ID_TRUE )
        {

            if( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsTypedef != ID_TRUE )
            {   // typedef 정의가 아닐경우
                /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
                 * 5th. problem : 정의되지 않은 구조체 포인터 변수 선언안됨. *
                 * 8th. problem : can't resolve extern variable type at declaring section. */
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct  == ID_TRUE) &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] != '\0') &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
                {   // struct 변수 선언의 경우.
                    // structure 변수 선언의경우 extern or pointer가 아니라면 struct table에서
                    // 해당 struct tag가 존재하는지 검사하며, extern or pointer일 경우에는 검사하지 않고
                    // 나중에 해당 변수를 사용할때 검사한다.
                    if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer  == 0) &&
                         (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsExtern == ID_FALSE) )
                    {   // it's not a pointer of struct and extern.
                        gUlpParseInfo.mStructPtr = gUlpStructT.ulpStructLookupAll(
                                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName,
                                            gUlpCurDepth );
                        if ( gUlpParseInfo.mStructPtr == NULL )
                        {
                            // error 처리

                            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                             ulpERR_ABORT_COMP_C_Unknown_Structname_Error,
                                             gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName );
                            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                        }
                        else
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                                    = gUlpParseInfo.mStructPtr;
                        }
                    }
                    else
                    {   // it's a point or extern of struct
                        // do nothing
                    }
                }
            }
            else
            {
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct   == ID_TRUE) &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
                {   // structure 를 typedef 정의할 경우.
                    if (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] == '\0')
                    {   // no tag structure 를 typedef 정의할 경우.
                        // ex) typedef struct { ... } A;
                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                                = gUlpParseInfo.mStructPtr;
                    }
                }
            }

            // char, varchar 변수의경우 -nchar_var 커맨드option에 포함된 변수인지 확인함.
            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR) ||
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) )
            {
                IDU_LIST_ITERATE(&gUlpProgOption.mNcharVarNameList, sIterator)
                {
                    sVarName = (SChar* )sIterator->mObj;
                    if ( idlOS::strcmp( sVarName,
                         gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName )
                         == 0 )
                    {
                        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR )
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NCHAR;
                        }
                        else
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NVARCHAR;
                        }
                    }
                }
            }

            // scope table에 해당 symbol node를 추가한다.
            if( (sSymNode = gUlpScopeT.ulpSAdd ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth],
                                                 gUlpCurDepth ))
                == NULL )
            {
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                ulpERR_ABORT_COMP_C_Add_Symbol_Error,
                                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }

            //varchar type의 경우, 나중 코드 변환을 위해 list에 따로 저장한다.
            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) ||
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_NVARCHAR)
               )
            {
                sVarcharListNode =
                    (iduListNode*)idlOS::malloc(ID_SIZEOF(iduListNode));
                if (sVarcharListNode == NULL)
                {
                    ulpSetErrorCode(&gUlpParseInfo.mErrorMgr, ulpERR_ABORT_Memory_Alloc_Error);
                    gUlpCOMPErrCode = ulpGetErrorSTATE(&gUlpParseInfo.mErrorMgr);
                    COMPerror(ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr));
                }
                else
                {
                    IDU_LIST_INIT_OBJ(sVarcharListNode, &(sSymNode->mElement));
                    IDU_LIST_ADD_LAST(&(gUlpParseInfo.mVarcharVarList), sVarcharListNode);
                }
            }

            /* BUG-35518 Shared pointer should be supported in APRE
             * Store tokens for shared pointer to convert */

            if ( gUlpParseInfo.mIsSharedPtr == ID_TRUE )
            {
                sSharedPtrVarListNode = (iduListNode*)idlOS::malloc(ID_SIZEOF(iduListNode));
                if (sSharedPtrVarListNode == NULL)
                {
                    ulpSetErrorCode(&gUlpParseInfo.mErrorMgr, ulpERR_ABORT_Memory_Alloc_Error);
                    gUlpCOMPErrCode = ulpGetErrorSTATE(&gUlpParseInfo.mErrorMgr);
                    COMPerror(ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr));
                }
                else
                {
                    IDU_LIST_INIT_OBJ(sSharedPtrVarListNode, &(sSymNode->mElement));
                    IDU_LIST_ADD_LAST(&(gUlpParseInfo.mSharedPtrVarList), sSharedPtrVarListNode);
                }

            }

        }
    ;}
    break;

  case 91:

/* Line 1455 of yacc.c  */
#line 924 "ulpCompy.y"
    {
        SChar *sVarName;
        ulpSymTNode *sSymNode;
        iduListNode *sIterator = NULL;
        iduListNode *sVarcharListNode = NULL;

        if( gUlpParseInfo.mFuncDecl != ID_TRUE )
        {

            if( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsTypedef != ID_TRUE )
            {   // typedef 정의가 아닐경우

                /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
                 * 5th. problem : 정의되지 않은 구조체 포인터 변수 선언안됨. *
                 * 8th. problem : can't resolve extern variable type at declaring section. */
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct  == ID_TRUE) &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] != '\0') &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
                {   // struct 변수 선언의 경우.
                    // structure 변수 선언의경우 pointer가 아니라면 struct table에서
                    // 해당 struct tag가 존재하는지 검사하며, pointer일 경우에는 검사하지 않고
                    // 나중에 해당 변수를 사용할때 검사한다.
                    if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer  == 0) &&
                         (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsExtern == ID_FALSE) )
                    {   // it's not a pointer of struct and extern.

                        gUlpParseInfo.mStructPtr = gUlpStructT.ulpStructLookupAll(
                                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName,
                                            gUlpCurDepth );
                        if ( gUlpParseInfo.mStructPtr == NULL )
                        {
                            // error 처리

                            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                             ulpERR_ABORT_COMP_C_Unknown_Structname_Error,
                                             gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName );
                            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                        }
                        else
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                                    = gUlpParseInfo.mStructPtr;
                        }
                    }
                    else
                    {   // it's a point of struct
                        // do nothing
                    }
                }
            }
            else
            {
                // no tag structure 를 typedef 할경우.
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct   == ID_TRUE) &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
                {   // structure 를 typedef 정의할 경우.
                    if (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] == '\0')
                    {   // no tag structure 를 typedef 정의할 경우.
                        // ex) typedef struct { ... } A;
                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink = gUlpParseInfo.mStructPtr;
                    }
                }
            }

            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR) ||
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) )
            {
                IDU_LIST_ITERATE(&gUlpProgOption.mNcharVarNameList, sIterator)
                {
                    sVarName = (SChar* )sIterator->mObj;
                    if ( idlOS::strcmp( sVarName, gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName )
                         == 0 )
                    {
                        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR )
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NCHAR;
                        }
                        else
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NVARCHAR;
                        }
                    }
                }
            }

            if( (sSymNode = gUlpScopeT.ulpSAdd ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth],
                                                 gUlpCurDepth ))
                == NULL )
            {
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                ulpERR_ABORT_COMP_C_Add_Symbol_Error,
                                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }

            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) ||
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_NVARCHAR) )
            {
                sVarcharListNode =
                    (iduListNode*)idlOS::malloc(ID_SIZEOF(iduListNode));
                if (sVarcharListNode == NULL)
                {
                    ulpSetErrorCode(&gUlpParseInfo.mErrorMgr, ulpERR_ABORT_Memory_Alloc_Error);
                    gUlpCOMPErrCode = ulpGetErrorSTATE(&gUlpParseInfo.mErrorMgr);
                    COMPerror(ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr));
                }
                else
                {
                    IDU_LIST_INIT_OBJ(sVarcharListNode, &(sSymNode->mElement));
                    IDU_LIST_ADD_LAST(&(gUlpParseInfo.mVarcharVarList), sVarcharListNode);
                }
            }
        }
    ;}
    break;

  case 92:

/* Line 1455 of yacc.c  */
#line 1046 "ulpCompy.y"
    {
        // , 를 사용한 동일 type을 여러개 선언할 경우 필요한 초기화.
        gUlpParseInfo.mSaveId = ID_TRUE;
        if ( gUlpParseInfo.mHostValInfo4Typedef != NULL )
        {
            if ( gUlpParseInfo.mHostValInfo4Typedef->mArraySize[0] != '\0' )
            {
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize,
                                gUlpParseInfo.mHostValInfo4Typedef->mArraySize,
                                MAX_NUMBER_LEN - 1 );
            }
            else
            {
                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize[0]   = '\0';
            }

            if ( gUlpParseInfo.mHostValInfo4Typedef->mArraySize2[0] != '\0' )
            {
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2,
                                gUlpParseInfo.mHostValInfo4Typedef->mArraySize2,
                                MAX_NUMBER_LEN - 1 );
            }
            else
            {
                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2[0]  = '\0';
            }

            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer
                    = gUlpParseInfo.mHostValInfo4Typedef->mPointer;
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsarray
                    = gUlpParseInfo.mHostValInfo4Typedef->mIsarray;
        }
        else
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize[0]   = '\0';
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2[0]  = '\0';
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer        = 0;
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsarray        = ID_FALSE;
        }

    ;}
    break;

  case 95:

/* Line 1455 of yacc.c  */
#line 1096 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsTypedef = ID_TRUE;
    ;}
    break;

  case 96:

/* Line 1455 of yacc.c  */
#line 1100 "ulpCompy.y"
    {
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                                 *
         * 8th. problem : can't resolve extern variable type at declaring section. */
        // extern 변수이고 standard type이 아니라면, 변수 선언시 type resolving을 하지않고,
        // 사용시 resolving을 하기위해 필요한 field.
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsExtern = ID_TRUE;
    ;}
    break;

  case 100:

/* Line 1455 of yacc.c  */
#line 1114 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_CHAR;
    ;}
    break;

  case 101:

/* Line 1455 of yacc.c  */
#line 1119 "ulpCompy.y"
    {
        /* BUG-31831 : An additional error message is needed to notify 
            the unacceptability of using varchar type in #include file. */
        if( gUlpCOMPIncludeIndex > 0 )
        {
            // error 처리
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Varchar_In_IncludeFile_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        gUlpParseInfo.mSaveId = ID_TRUE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_VARCHAR;
    ;}
    break;

  case 102:

/* Line 1455 of yacc.c  */
#line 1134 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NCHAR;
    ;}
    break;

  case 103:

/* Line 1455 of yacc.c  */
#line 1139 "ulpCompy.y"
    {
        /* BUG-31831 : An additional error message is needed to notify 
            the unacceptability of using varchar type in #include file. */
        if( gUlpCOMPIncludeIndex > 0 )
        {
            // error 처리
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Varchar_In_IncludeFile_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        gUlpParseInfo.mSaveId = ID_TRUE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NVARCHAR;
    ;}
    break;

  case 104:

/* Line 1455 of yacc.c  */
#line 1154 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_SHORT;
    ;}
    break;

  case 105:

/* Line 1455 of yacc.c  */
#line 1159 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        switch ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType )
        {
            case H_SHORT:
            case H_LONG:
                break;
            default:
                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_INT;
                break;
        }
    ;}
    break;

  case 106:

/* Line 1455 of yacc.c  */
#line 1173 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_LONG )
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_LONGLONG;
        }
        else
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_LONG;
        }
    ;}
    break;

  case 107:

/* Line 1455 of yacc.c  */
#line 1186 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIssign = ID_TRUE;
    ;}
    break;

  case 108:

/* Line 1455 of yacc.c  */
#line 1190 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIssign = ID_FALSE;
    ;}
    break;

  case 109:

/* Line 1455 of yacc.c  */
#line 1194 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_FLOAT;
    ;}
    break;

  case 110:

/* Line 1455 of yacc.c  */
#line 1200 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_DOUBLE;
    ;}
    break;

  case 113:

/* Line 1455 of yacc.c  */
#line 1208 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_UNKNOWN;
    ;}
    break;

  case 114:

/* Line 1455 of yacc.c  */
#line 1214 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_USER_DEFINED;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct = ID_TRUE;
    ;}
    break;

  case 115:

/* Line 1455 of yacc.c  */
#line 1221 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_UNKNOWN;
    ;}
    break;

  case 116:

/* Line 1455 of yacc.c  */
#line 1227 "ulpCompy.y"
    {
        // In case of struct type or typedef type
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.ulpCopyHostInfo4Typedef( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth],
                                               gUlpParseInfo.mHostValInfo4Typedef );
    ;}
    break;

  case 117:

/* Line 1455 of yacc.c  */
#line 1235 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_BINARY;
    ;}
    break;

  case 118:

/* Line 1455 of yacc.c  */
#line 1241 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_BIT;
    ;}
    break;

  case 119:

/* Line 1455 of yacc.c  */
#line 1247 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_BYTES;
    ;}
    break;

  case 120:

/* Line 1455 of yacc.c  */
#line 1253 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;
        
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_VARBYTE;
    ;}
    break;

  case 121:

/* Line 1455 of yacc.c  */
#line 1259 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NIBBLE;
    ;}
    break;

  case 122:

/* Line 1455 of yacc.c  */
#line 1265 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_INTEGER;
    ;}
    break;

  case 123:

/* Line 1455 of yacc.c  */
#line 1271 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NUMERIC;
    ;}
    break;

  case 124:

/* Line 1455 of yacc.c  */
#line 1277 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_BLOBLOCATOR;
    ;}
    break;

  case 125:

/* Line 1455 of yacc.c  */
#line 1283 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_CLOBLOCATOR;
    ;}
    break;

  case 126:

/* Line 1455 of yacc.c  */
#line 1289 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_BLOB;
    ;}
    break;

  case 127:

/* Line 1455 of yacc.c  */
#line 1295 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_CLOB;
    ;}
    break;

  case 128:

/* Line 1455 of yacc.c  */
#line 1301 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        if( ID_SIZEOF(SQLLEN) == 4 )
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_INT;
        }
        else
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_LONG;
        }
        // SQLLEN 은 무조건 signed
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIssign = ID_TRUE;
    ;}
    break;

  case 129:

/* Line 1455 of yacc.c  */
#line 1316 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_TIMESTAMP;
    ;}
    break;

  case 130:

/* Line 1455 of yacc.c  */
#line 1322 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_TIME;
    ;}
    break;

  case 131:

/* Line 1455 of yacc.c  */
#line 1328 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_DATE;
    ;}
    break;

  case 132:

/* Line 1455 of yacc.c  */
#line 1335 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_SQLDA;
    ;}
    break;

  case 133:

/* Line 1455 of yacc.c  */
#line 1340 "ulpCompy.y"
    {
        gUlpParseInfo.mSaveId = ID_TRUE;

        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_FAILOVERCB;
    ;}
    break;

  case 136:

/* Line 1455 of yacc.c  */
#line 1357 "ulpCompy.y"
    {
        if ( gUlpParseInfo.mStructDeclDepth > 0 )
        {
            idlOS::free( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] );
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] = NULL;
        }
        gUlpParseInfo.mStructDeclDepth--;
        if( gUlpParseInfo.mStructPtr != NULL )
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                = gUlpParseInfo.mStructPtr;
        }
    ;}
    break;

  case 137:

/* Line 1455 of yacc.c  */
#line 1371 "ulpCompy.y"
    {
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
         * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
        if ( gUlpParseInfo.mStructDeclDepth > 0 )
        {
            idlOS::free( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] );
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] = NULL;
        }

        gUlpParseInfo.mStructDeclDepth--;

        // typedef struct 의 경우 mStructLink가 설정되지 않는다.
        // 이 경우 mStructLink가가 설정되는 시점은 해당 type을 이용해 변수를 선언하는 시점이다.
        if( gUlpParseInfo.mStructPtr != NULL )
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                = gUlpParseInfo.mStructPtr;
        }
    ;}
    break;

  case 138:

/* Line 1455 of yacc.c  */
#line 1394 "ulpCompy.y"
    {
        if ( gUlpParseInfo.mStructDeclDepth > 0 )
        {
            idlOS::free( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] );
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] = NULL;
        }
        gUlpParseInfo.mStructDeclDepth--;
        if( gUlpParseInfo.mStructPtr != NULL )
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                    = gUlpParseInfo.mStructPtr;
        }
    ;}
    break;

  case 139:

/* Line 1455 of yacc.c  */
#line 1408 "ulpCompy.y"
    {
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
         * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
        if ( gUlpParseInfo.mStructDeclDepth > 0 )
        {
            idlOS::free( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] );
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] = NULL;
        }
        gUlpParseInfo.mStructDeclDepth--;
        if( gUlpParseInfo.mStructPtr != NULL )
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                    = gUlpParseInfo.mStructPtr;
        }
    ;}
    break;

  case 140:

/* Line 1455 of yacc.c  */
#line 1424 "ulpCompy.y"
    {
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
         * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
        if ( gUlpParseInfo.mStructDeclDepth > 0 )
        {
            idlOS::free( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] );
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] = NULL;
        }

        gUlpParseInfo.mStructDeclDepth--;

        /* BUG-27875 : 구조체안의 typedef type인식못함. */
        gUlpParseInfo.mSkipTypedef = ID_FALSE;

        /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
         * 2th. problem : 빈구조체 선언이 허용안됨. ex) struct A; *
         * 5th. problem : 정의되지 않은 구조체 포인터 변수 선언안됨. */
        // structure 이름 정보 저장함.
        idlOS::strcpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName,
                       (yyvsp[(2) - (2)].strval) );
    ;}
    break;

  case 141:

/* Line 1455 of yacc.c  */
#line 1449 "ulpCompy.y"
    {
        /* BUG-27875 : 구조체안의 typedef type인식못함. */
        gUlpParseInfo.mSkipTypedef = ID_FALSE;
        // id가 struct table에 있는지 확인한다.
        if ( gUlpStructT.ulpStructLookup( (yyvsp[(1) - (2)].strval), gUlpCurDepth - 1 )
             != NULL )
        {
            // error 처리
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_C_Duplicate_Structname_Error,
                             (yyvsp[(1) - (2)].strval) );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {

            idlOS::strcpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructName,
                           (yyvsp[(1) - (2)].strval) );
            // struct table에 저장한다.
            /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
             * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink
                    = gUlpStructT.ulpStructAdd ( (yyvsp[(1) - (2)].strval), gUlpCurDepth );

            if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink
                 == NULL )
            {
                // error 처리
                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_C_Duplicate_Structname_Error,
                                 (yyvsp[(1) - (2)].strval) );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }
        }
    ;}
    break;

  case 142:

/* Line 1455 of yacc.c  */
#line 1490 "ulpCompy.y"
    {
        /* BUG-27875 : 구조체안의 typedef type인식못함. */
        gUlpParseInfo.mSkipTypedef = ID_FALSE;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructName[0] = '\0';
        // struct table에 저장한다.
        // no tag struct node는 hash table 마지막 bucket에 추가된다.
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
         * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink
                = gUlpStructT.ulpNoTagStructAdd ();
    ;}
    break;

  case 143:

/* Line 1455 of yacc.c  */
#line 1505 "ulpCompy.y"
    {
        /* BUG-27875 : 구조체안의 typedef type인식못함. */
        // 아래 구문을 처리하기위해 mSkipTypedef 변수 추가됨.
        // typedef struct Struct1 Struct1;
        // struct Struct1       <- mSkipTypedef = ID_TRUE  :
        //                          Struct1은 비록 이전에 typedef되어 있지만 렉서에서 C_TYPE_NAME이아닌
        // {                        C_IDENTIFIER로 인식되어야 한다.
        //    ...               <- mSkipTypedef = ID_FALSE :
        //    ...                   필드에 typedef 이름이 오면 C_TYPE_NAME으로 인식돼야한다.
        // };
        gUlpParseInfo.mSkipTypedef = ID_TRUE;
        gUlpParseInfo.mStructDeclDepth++;
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
         * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
        if( gUlpParseInfo.mStructDeclDepth >= MAX_NESTED_STRUCT_DEPTH )
        {
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Exceed_Max_Nested_Struct_Depth_Error );
            ulpPrintfErrorCode( stderr,
                                &gUlpParseInfo.mErrorMgr);
            IDE_ASSERT(0);
        }
        else
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]
                    = (ulpSymTElement *)idlOS::malloc(ID_SIZEOF( ulpSymTElement));
            if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] == NULL )
            {
                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_Memory_Alloc_Error );
                ulpPrintfErrorCode( stderr,
                                    &gUlpParseInfo.mErrorMgr);
                IDE_ASSERT(0);
            }
            else
            {
                (void) gUlpParseInfo.ulpInitHostInfo();
            }
        }
        gUlpParseInfo.mSaveId      = ID_TRUE;
    ;}
    break;

  case 144:

/* Line 1455 of yacc.c  */
#line 1547 "ulpCompy.y"
    {
        /* BUG-27875 : 구조체안의 typedef type인식못함. */
        gUlpParseInfo.mSkipTypedef = ID_TRUE;
        gUlpParseInfo.mStructDeclDepth++;
        /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
         * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
        if( gUlpParseInfo.mStructDeclDepth >= MAX_NESTED_STRUCT_DEPTH )
        {
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Exceed_Max_Nested_Struct_Depth_Error );
            ulpPrintfErrorCode( stderr,
                                &gUlpParseInfo.mErrorMgr);
            IDE_ASSERT(0);
        }
        else
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]
                    = (ulpSymTElement *)idlOS::malloc(ID_SIZEOF( ulpSymTElement));
            if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth] == NULL )
            {
                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_Memory_Alloc_Error );
                ulpPrintfErrorCode( stderr,
                                    &gUlpParseInfo.mErrorMgr);
                IDE_ASSERT(0);
            }
            else
            {
                (void) gUlpParseInfo.ulpInitHostInfo();
            }
        }
        gUlpParseInfo.mSaveId      = ID_TRUE;
    ;}
    break;

  case 149:

/* Line 1455 of yacc.c  */
#line 1596 "ulpCompy.y"
    {
        iduListNode *sIterator = NULL;
        iduListNode *sNextNode = NULL;
        ulpSymTElement *sSymNode;

        if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) ||
             (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_NVARCHAR) )
        {
            if ( gUlpParseInfo.mFuncDecl != ID_TRUE )
            {
                WRITESTR2BUFCOMP ( (SChar *)" */\n" );

                /* BUG-26375 valgrind bug */
                IDU_LIST_ITERATE_SAFE(&(gUlpParseInfo.mVarcharVarList),
                                        sIterator, sNextNode)
                {
                    sSymNode = (ulpSymTElement *)sIterator->mObj;
                    if ( gDontPrint2file != ID_TRUE )
                    {
                        gUlpCodeGen.ulpGenVarchar( sSymNode );
                    }
                    IDU_LIST_REMOVE(sIterator);
                    idlOS::free(sIterator);
                }
                IDU_LIST_INIT( &(gUlpParseInfo.mVarcharVarList) );
                gUlpParseInfo.mVarcharDecl = ID_FALSE;
            }
        }

        gUlpParseInfo.mHostValInfo4Typedef = NULL;
        gUlpParseInfo.ulpInitHostInfo();
    ;}
    break;

  case 151:

/* Line 1455 of yacc.c  */
#line 1636 "ulpCompy.y"
    {
        SChar       *sVarName;
        ulpSymTNode *sSymNode;
        iduListNode *sIterator = NULL;
        iduListNode *sVarcharListNode = NULL;

        // field 이름 중복 검사함.
        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink->mChild->ulpSymLookup
             ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName ) != NULL )
        {
            // error 처리
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_C_Duplicate_Structname_Error,
                             gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
             * 5th. problem : 정의되지 않은 구조체 포인터 변수 선언안됨. *
             * 8th. problem : can't resolve extern variable type at declaring section. */
            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct  == ID_TRUE) &&
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] != '\0') &&
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
            {   // struct 변수 선언의 경우.
                // structure 변수 선언의경우 pointer가 아니라면 struct table에서
                // 해당 struct tag가 존재하는지 검사하며, pointer일 경우에는 검사하지 않고
                // 나중에 해당 변수를 사용할때 검사한다.
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer  == 0) &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsExtern == ID_FALSE) )
                {   // it's not a pointer of struct and extern.

                    gUlpParseInfo.mStructPtr = gUlpStructT.ulpStructLookupAll(
                                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName,
                                        gUlpCurDepth );
                    if ( gUlpParseInfo.mStructPtr == NULL )
                    {
                        // error 처리

                        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                        ulpERR_ABORT_COMP_C_Unknown_Structname_Error,
                                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName );
                        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                        COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                    }
                    else
                    {
                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                                = gUlpParseInfo.mStructPtr;
                    }
                }
                else
                {   // it's a point of struct
                    // do nothing
                }
            }

            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR) ||
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) )
            {
                IDU_LIST_ITERATE(&gUlpProgOption.mNcharVarNameList, sIterator)
                {
                    sVarName = (SChar* )sIterator->mObj;
                    if ( idlOS::strcmp( sVarName, gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName )
                         == 0 )
                    {
                        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR )
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NCHAR;
                        }
                        else
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NVARCHAR;
                        }
                    }
                }
            }

            /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
             * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
            // struct 필드를 add하려 한다면, mHostValInfo의 이전 index에 저장된 struct node pointer 를 이용해야함.
            sSymNode =
                    gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink
                    ->mChild->ulpSymAdd(
                                           gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]
                                       );

            if ( sSymNode != NULL )
            {
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) ||
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_NVARCHAR) )
                {
                    sVarcharListNode =
                        (iduListNode*)idlOS::malloc(ID_SIZEOF(iduListNode));
                    if (sVarcharListNode == NULL)
                    {
                        ulpSetErrorCode(&gUlpParseInfo.mErrorMgr, ulpERR_ABORT_Memory_Alloc_Error);
                        gUlpCOMPErrCode = ulpGetErrorSTATE(&gUlpParseInfo.mErrorMgr);
                        COMPerror(ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr));
                    }
                    else
                    {
                        IDU_LIST_INIT_OBJ(sVarcharListNode, &(sSymNode->mElement));
                        IDU_LIST_ADD_LAST(&(gUlpParseInfo.mVarcharVarList), sVarcharListNode);
                    }
                }
            }
        }
    ;}
    break;

  case 152:

/* Line 1455 of yacc.c  */
#line 1747 "ulpCompy.y"
    {
        SChar *sVarName;
        ulpSymTNode *sSymNode;
        iduListNode *sIterator = NULL;
        iduListNode *sVarcharListNode = NULL;

        // field 이름 중복 검사함.
        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink->mChild->ulpSymLookup
             ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName ) != NULL )
        {
            // error 처리
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_C_Duplicate_Structname_Error,
                             gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
             * 5th. problem : 정의되지 않은 구조체 포인터 변수 선언안됨. *
             * 8th. problem : can't resolve extern variable type at declaring section. */
            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct  == ID_TRUE) &&
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] != '\0') &&
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
            {   // struct 변수 선언의 경우.
                // structure 변수 선언의경우 pointer가 아니라면 struct table에서
                // 해당 struct tag가 존재하는지 검사하며, pointer일 경우에는 검사하지 않고
                // 나중에 해당 변수를 사용할때 검사한다.
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer  == 0) &&
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsExtern == ID_FALSE) )
                {   // it's not a pointer of struct and extern.

                    gUlpParseInfo.mStructPtr = gUlpStructT.ulpStructLookupAll(
                                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName,
                                        gUlpCurDepth );
                    if ( gUlpParseInfo.mStructPtr == NULL )
                    {
                        // error 처리

                        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                        ulpERR_ABORT_COMP_C_Unknown_Structname_Error,
                                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName );
                        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                        COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                    }
                    else
                    {
                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                                = gUlpParseInfo.mStructPtr;
                    }
                }
                else
                {   // it's a point of struct
                    // do nothing
                }
            }

            if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR) ||
                 (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) )
            {
                IDU_LIST_ITERATE(&gUlpProgOption.mNcharVarNameList, sIterator)
                {
                    sVarName = (SChar* )sIterator->mObj;
                    if ( idlOS::strcmp( sVarName, gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName )
                         == 0 )
                    {
                        if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR )
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NCHAR;
                        }
                        else
                        {
                            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NVARCHAR;
                        }
                    }
                }
            }

            /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
             * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
            // struct 필드를 add하려 한다면, mHostValInfo의 이전 index에 저장된 struct node pointer 를 이용해야함.
            sSymNode =
                  gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth - 1]->mStructLink
                  ->mChild->ulpSymAdd (
                                          gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]
                                      );

            if ( sSymNode != NULL )
            {
                if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) ||
                     (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_NVARCHAR) )
                {
                    sVarcharListNode =
                        (iduListNode*)idlOS::malloc(ID_SIZEOF(iduListNode));
                    if (sVarcharListNode == NULL)
                    {
                        ulpSetErrorCode(&gUlpParseInfo.mErrorMgr, ulpERR_ABORT_Memory_Alloc_Error);
                        gUlpCOMPErrCode = ulpGetErrorSTATE(&gUlpParseInfo.mErrorMgr);
                        COMPerror(ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr));
                    }
                    else
                    {
                        IDU_LIST_INIT_OBJ(sVarcharListNode, &(sSymNode->mElement));
                        IDU_LIST_ADD_LAST(&(gUlpParseInfo.mVarcharVarList), sVarcharListNode);
                    }
                }
            }
        }
    ;}
    break;

  case 153:

/* Line 1455 of yacc.c  */
#line 1861 "ulpCompy.y"
    {
        // , 를 사용한 동일 type을 여러개 선언할 경우 필요한 초기화.
        gUlpParseInfo.mSaveId = ID_TRUE;
        if ( gUlpParseInfo.mHostValInfo4Typedef != NULL )
        {
            if ( gUlpParseInfo.mHostValInfo4Typedef->mArraySize[0] != '\0' )
            {
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize,
                                gUlpParseInfo.mHostValInfo4Typedef->mArraySize,
                                MAX_NUMBER_LEN - 1 );
            }
            else
            {
                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize[0]   = '\0';
            }

            if ( gUlpParseInfo.mHostValInfo4Typedef->mArraySize2[0] != '\0' )
            {
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2,
                                gUlpParseInfo.mHostValInfo4Typedef->mArraySize2,
                                MAX_NUMBER_LEN - 1 );
            }
            else
            {
                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2[0]  = '\0';
            }

            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer
                    = gUlpParseInfo.mHostValInfo4Typedef->mPointer;
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsarray
                    = gUlpParseInfo.mHostValInfo4Typedef->mIsarray;
        }
        else
        {
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize[0]   = '\0';
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2[0]  = '\0';
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer        = 0;
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsarray        = ID_FALSE;
        }
    ;}
    break;

  case 164:

/* Line 1455 of yacc.c  */
#line 1927 "ulpCompy.y"
    {
        gUlpParseInfo.mConstantExprStr[0] = '\0';
        gUlpParseInfo.mArrDepth = 0;
    ;}
    break;

  case 165:

/* Line 1455 of yacc.c  */
#line 1932 "ulpCompy.y"
    {
        gUlpParseInfo.mConstantExprStr[0] = '\0';
        gUlpParseInfo.mArrDepth = 0;
    ;}
    break;

  case 168:

/* Line 1455 of yacc.c  */
#line 1942 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer ++;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsarray = ID_TRUE;
        if( gUlpParseInfo.mArrDepth == 0 )
        {
            if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize[0] == '\0' )
            {
                // do nothing
            }
            else
            {
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2,
                                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize,
                                MAX_NUMBER_LEN - 1 );
            }
        }
        else if ( gUlpParseInfo.mArrDepth == 1 )
        {
            // 2차 배열까지만 처리함.
            gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2[0] = '\0';
        }
        else
        {
            // 2차 배열까지만 처리함.
            // ignore
        }

        gUlpParseInfo.mArrDepth++;
    ;}
    break;

  case 169:

/* Line 1455 of yacc.c  */
#line 1972 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer ++;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsarray = ID_TRUE;

        if( gUlpParseInfo.mArrDepth == 0 )
        {
            if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize[0] == '\0' )
            {
                // 1차 배열의 expr
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize,
                                gUlpParseInfo.mConstantExprStr,
                                MAX_NUMBER_LEN - 1 );
            }
            else
            {
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2,
                                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize,
                                MAX_NUMBER_LEN - 1 );
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize,
                                gUlpParseInfo.mConstantExprStr,
                                MAX_NUMBER_LEN - 1 );
            }

        }
        else if ( gUlpParseInfo.mArrDepth == 1 )
        {
            if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2[0] == '\0' )
            {
                // 2차 배열의 expr
                idlOS::strncpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mArraySize2,
                                gUlpParseInfo.mConstantExprStr,
                                MAX_NUMBER_LEN - 1 );
            }
            else
            {
                // do nothing
            }
        }

        gUlpParseInfo.mArrExpr = ID_FALSE;
        gUlpParseInfo.mArrDepth++;
    ;}
    break;

  case 171:

/* Line 1455 of yacc.c  */
#line 2016 "ulpCompy.y"
    {
        gUlpCurDepth--;
    ;}
    break;

  case 173:

/* Line 1455 of yacc.c  */
#line 2024 "ulpCompy.y"
    {
        // array [ expr ] => expr 의 시작이라는 것을 알림. expr을 저장하기 위함.
        // 물론 expr 문법 체크도 함.
        gUlpParseInfo.mConstantExprStr[0] = '\0';
        gUlpParseInfo.mArrExpr = ID_TRUE;
    ;}
    break;

  case 174:

/* Line 1455 of yacc.c  */
#line 2034 "ulpCompy.y"
    {
        gUlpCurDepth++;
        gUlpParseInfo.mFuncDecl = ID_TRUE;
    ;}
    break;

  case 175:

/* Line 1455 of yacc.c  */
#line 2042 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer ++;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mAlloc = ID_TRUE;
    ;}
    break;

  case 176:

/* Line 1455 of yacc.c  */
#line 2047 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer ++;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mAlloc = ID_TRUE;
    ;}
    break;

  case 177:

/* Line 1455 of yacc.c  */
#line 2052 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer ++;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mAlloc = ID_TRUE;
    ;}
    break;

  case 178:

/* Line 1455 of yacc.c  */
#line 2057 "ulpCompy.y"
    {
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mPointer ++;
        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mAlloc = ID_TRUE;
    ;}
    break;

  case 189:

/* Line 1455 of yacc.c  */
#line 2091 "ulpCompy.y"
    {
        SChar *sVarName;
        iduListNode *sIterator = NULL;

        /* BUG-28118 : system 헤더파일들도 파싱돼야함.            *
         * 5th. problem : 정의되지 않은 구조체 포인터 변수 선언안됨. */
        if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mIsstruct  == ID_TRUE) &&
             (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName[0] != '\0') &&
             (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink == NULL) )
        {   // struct 변수 선언의 경우, type check rigidly.

            gUlpParseInfo.mStructPtr = gUlpStructT.ulpStructLookupAll(
                                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName,
                                gUlpCurDepth );
            if ( gUlpParseInfo.mStructPtr == NULL )
            {
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_C_Unknown_Structname_Error,
                                 gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructName );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }
            else
            {
                gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mStructLink
                        = gUlpParseInfo.mStructPtr;
            }

        }

        if ( (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR) ||
             (gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_VARCHAR) )
        {
            IDU_LIST_ITERATE(&gUlpProgOption.mNcharVarNameList, sIterator)
            {
                sVarName = (SChar* )sIterator->mObj;
                if ( idlOS::strcmp( sVarName, gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName )
                     == 0 )
                {
                    if ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType == H_CHAR )
                    {
                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NCHAR;
                    }
                    else
                    {
                        gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mType = H_NVARCHAR;
                    }
                }
            }
        }

        if( gUlpScopeT.ulpSAdd ( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]
                                 , gUlpCurDepth )
            == NULL )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_C_Add_Symbol_Error,
                             gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }

        gUlpParseInfo.ulpInitHostInfo();
    ;}
    break;

  case 225:

/* Line 1455 of yacc.c  */
#line 2224 "ulpCompy.y"
    {
        /* BUG-29081 : 변수 선언부가 statement 중간에 들어오면 파싱 에러발생. */
        // statement 를 파싱한뒤 변수 type정보를 저장해두고 있는 자료구조를 초기화해줘야한다.
        // 저장 자체를 안하는게 이상적이나 type처리 문법을 선언부와 함께 공유하므로 어쩔수 없다.
        gUlpParseInfo.ulpInitHostInfo();
    ;}
    break;

  case 229:

/* Line 1455 of yacc.c  */
#line 2240 "ulpCompy.y"
    {
        if( gUlpParseInfo.mFuncDecl == ID_TRUE )
        {
            gUlpParseInfo.mFuncDecl = ID_FALSE;
        }
    ;}
    break;

  case 256:

/* Line 1455 of yacc.c  */
#line 2297 "ulpCompy.y"
    {
        if( idlOS::strlen((yyvsp[(1) - (1)].strval)) >= MAX_HOSTVAR_NAME_SIZE )
        {
            //error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_C_Exceed_Max_Id_Length_Error,
                             (yyvsp[(1) - (1)].strval) );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            if( gUlpParseInfo.mSaveId == ID_TRUE )
            {
                idlOS::strcpy( gUlpParseInfo.mHostValInfo[gUlpParseInfo.mStructDeclDepth]->mName,
                               (yyvsp[(1) - (1)].strval) );
                gUlpParseInfo.mSaveId = ID_FALSE;
            }
        }
    ;}
    break;

  case 259:

/* Line 1455 of yacc.c  */
#line 2333 "ulpCompy.y"
    {
            /* BUG-28061 : preprocessing을마치면 marco table을 초기화하고, *
             *             ulpComp 에서 재구축한다.                       */
            gUlpCOMPStartCond = gUlpCOMPPrevCond;
        ;}
    break;

  case 260:

/* Line 1455 of yacc.c  */
#line 2339 "ulpCompy.y"
    {
            gUlpCOMPStartCond = gUlpCOMPPrevCond;
        ;}
    break;

  case 261:

/* Line 1455 of yacc.c  */
#line 2343 "ulpCompy.y"
    {
            gUlpCOMPStartCond = gUlpCOMPPrevCond;
        ;}
    break;

  case 262:

/* Line 1455 of yacc.c  */
#line 2347 "ulpCompy.y"
    {
            /* macro 조건문의 경우 참이면 C상태, 거짓이면 MACRO_IFSKIP 상태로
             * 전이 된다. */
        ;}
    break;

  case 263:

/* Line 1455 of yacc.c  */
#line 2352 "ulpCompy.y"
    {
            /* macro 조건문의 경우 참이면 C상태, 거짓이면 MACRO_IFSKIP 상태로
             * 전이 된다. */
        ;}
    break;

  case 264:

/* Line 1455 of yacc.c  */
#line 2357 "ulpCompy.y"
    {
            /* macro 조건문의 경우 참이면 C상태, 거짓이면 MACRO_IFSKIP 상태로
             * 전이 된다. */
        ;}
    break;

  case 265:

/* Line 1455 of yacc.c  */
#line 2362 "ulpCompy.y"
    {
            /* macro 조건문의 경우 참이면 C상태, 거짓이면 MACRO_IFSKIP 상태로
             * 전이 된다. */
        ;}
    break;

  case 266:

/* Line 1455 of yacc.c  */
#line 2367 "ulpCompy.y"
    {
            /* macro 조건문의 경우 참이면 C상태, 거짓이면 MACRO_IFSKIP 상태로
             * 전이 된다. */
        ;}
    break;

  case 268:

/* Line 1455 of yacc.c  */
#line 2376 "ulpCompy.y"
    {
            /* #include <...> */

            // 1. check exist header file in include paths
            if ( gUlpProgOption.ulpLookupHeader( (yyvsp[(3) - (4)].strval), ID_TRUE )
                 == IDE_FAILURE )
            {
                // do nothing
            }
            else
            {

                // 현재 #include 처리다.
                gDontPrint2file = ID_TRUE;
                /* BUG-27683 : iostream 사용 제거 */
                // 2. flex 버퍼 상태 저장.
                ulpCOMPSaveBufferState();
                // 3. doCOMPparse()를 재호출한다.
                doCOMPparse( gUlpProgOption.ulpGetIncList() );
                // 전에 #inlcude 처리중이었나? 확인함
                gDontPrint2file = gUlpProgOption.ulpIsHeaderCInclude();

                // 4. precompiler를 실행한 directory를 current path로 재setting
                idlOS::strcpy( gUlpProgOption.mCurrentPath, gUlpProgOption.mStartPath );
            }

        ;}
    break;

  case 269:

/* Line 1455 of yacc.c  */
#line 2404 "ulpCompy.y"
    {

            // 1. check exist header file in include paths
            if ( gUlpProgOption.ulpLookupHeader( (yyvsp[(3) - (4)].strval), ID_TRUE )
                 == IDE_FAILURE )
            {
                // do nothing
            }
            else
            {

                // 현재 #include 처리다.
                gDontPrint2file = ID_TRUE;
                /* BUG-27683 : iostream 사용 제거 */
                // 2. flex 버퍼 상태 저장.
                ulpCOMPSaveBufferState();
                // 3. doCOMPparse()를 재호출한다.
                doCOMPparse( gUlpProgOption.ulpGetIncList() );
                // 전에 #inlcude 처리중이었나? 확인함
                gDontPrint2file = gUlpProgOption.ulpIsHeaderCInclude();

                // 4. precompiler를 실행한 directory를 current path로 재setting
                idlOS::strcpy( gUlpProgOption.mCurrentPath, gUlpProgOption.mStartPath );
            }

        ;}
    break;

  case 270:

/* Line 1455 of yacc.c  */
#line 2436 "ulpCompy.y"
    {
            SChar sTmpDEFtext[ MAX_MACRO_DEFINE_CONTENT_LEN ];
            idlOS::memset(sTmpDEFtext,0,MAX_MACRO_DEFINE_CONTENT_LEN);

            ulpCOMPEraseBN4MacroText( sTmpDEFtext , ID_FALSE );

            if ( sTmpDEFtext[0] == '\0' )
            {
                // macro symbol table에 추가함.
                if( gUlpMacroT.ulpMDefine( (yyvsp[(2) - (2)].strval), NULL, ID_FALSE ) == IDE_FAILURE )
                {

                    ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                     ulpERR_ABORT_Memory_Alloc_Error );
                    gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                    COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                }
            }
            else
            {
                // macro symbol table에 추가함.
                if( gUlpMacroT.ulpMDefine( (yyvsp[(2) - (2)].strval), sTmpDEFtext, ID_FALSE ) == IDE_FAILURE )
                {

                    ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                     ulpERR_ABORT_Memory_Alloc_Error );
                    gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                    COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                }
            }

        ;}
    break;

  case 271:

/* Line 1455 of yacc.c  */
#line 2469 "ulpCompy.y"
    {
            // function macro의경우 인자 정보는 따로 저장되지 않는다.
            SChar sTmpDEFtext[ MAX_MACRO_DEFINE_CONTENT_LEN ];

            idlOS::memset(sTmpDEFtext,0,MAX_MACRO_DEFINE_CONTENT_LEN);
            ulpCOMPEraseBN4MacroText( sTmpDEFtext , ID_FALSE );

            // #define A() {...} 이면, macro id는 A이다.
            if ( sTmpDEFtext[0] == '\0' )
            {
                // macro symbol table에 추가함.
                if ( gUlpMacroT.ulpMDefine( (yyvsp[(2) - (2)].strval), NULL, ID_TRUE ) == IDE_FAILURE )
                {

                    ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                     ulpERR_ABORT_Memory_Alloc_Error );
                    gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                    COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                }
            }
            else
            {
                // macro symbol table에 추가함.
                if ( gUlpMacroT.ulpMDefine( (yyvsp[(2) - (2)].strval), sTmpDEFtext, ID_TRUE ) == IDE_FAILURE )
                {

                    ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                     ulpERR_ABORT_Memory_Alloc_Error );
                    gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                    COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                }
            }

        ;}
    break;

  case 272:

/* Line 1455 of yacc.c  */
#line 2507 "ulpCompy.y"
    {
            // $<strval>2 를 macro symbol table에서 삭제 한다.
            gUlpMacroT.ulpMUndef( (yyvsp[(2) - (2)].strval) );
        ;}
    break;

  case 273:

/* Line 1455 of yacc.c  */
#line 2515 "ulpCompy.y"
    {
            SInt  sVal;
            SChar sTmpExpBuf[MAX_MACRO_IF_EXPR_LEN];
            /* BUG-32413 APRE memory allocation failure should be fixed */
            idlOS::memset(sTmpExpBuf, 0, MAX_MACRO_IF_EXPR_LEN);

            switch( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpPrevIfStatus() )
            {
                // 이전 상태가 PP_IF_IGNORE 이면 계속 무시함.
                case PP_IF_IGNORE :
                    // 단순히 token만 소모하는 역할이다. PPIFparse 호출하지 않는다.
                    ulpCOMPEraseBN4MacroText( sTmpExpBuf , ID_TRUE );
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IF, PP_IF_IGNORE );
                    break;
                // 이전 상태가 PP_IF_TRUE 이면 이번 #if <expr>파싱하여 값을 확인해봐야함.
                case PP_IF_TRUE :
                    // #if expression 을 복사해온다.
                    ulpCOMPEraseBN4MacroText( sTmpExpBuf , ID_TRUE );
                    gUlpPPIFbufptr = sTmpExpBuf;
                    gUlpPPIFbuflim = sTmpExpBuf + idlOS::strlen(sTmpExpBuf);

                    if ( PPIFparse( sTmpExpBuf, &sVal ) != 0 )
                    {
                        //error 처리

                        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                         ulpERR_ABORT_COMP_IF_Macro_Syntax_Error );
                        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                        COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                    }
                    /* macro 조건문의 경우 참이면 MACRO상태, 거짓이면 MACRO_IFSKIP 상태로
                    * 전이 된다. */
                    if ( sVal != 0 )
                    {
                        // true
                        gUlpCOMPStartCond = gUlpCOMPPrevCond;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IF, PP_IF_TRUE );
                    }
                    else
                    {
                        // false
                        gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IF, PP_IF_FALSE );
                    }
                    break;
                // 이전 상태가 PP_IF_FALSE 이면 무시함.
                case PP_IF_FALSE :
                    // 단순히 token만 소모하는 역할이다. PPIFparse 호출하지 않는다.
                    ulpCOMPEraseBN4MacroText( sTmpExpBuf , ID_TRUE );
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IF, PP_IF_IGNORE );
                    break;

                default:
                    IDE_ASSERT(0);
            }
        ;}
    break;

  case 274:

/* Line 1455 of yacc.c  */
#line 2581 "ulpCompy.y"
    {
            SInt  sVal;
            SChar sTmpExpBuf[MAX_MACRO_IF_EXPR_LEN];
            /* BUG-32413 APRE memory allocation failure should be fixed */
            idlOS::memset(sTmpExpBuf, 0, MAX_MACRO_IF_EXPR_LEN);

            // #elif 순서 문법 검사.
            if ( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfCheckGrammar( PP_ELIF )
                 == ID_FALSE )
            {
                //error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_ELIF_Macro_Sequence_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }

            switch( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpPrevIfStatus() )
            {
                case PP_IF_IGNORE :
                    // 단순히 token만 소모하는 역할이다. PPIFparse 호출하지 않는다.
                    ulpCOMPEraseBN4MacroText( sTmpExpBuf , ID_TRUE );
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_ELIF, PP_IF_IGNORE );
                    break;

                case PP_IF_TRUE :
                    // 단순히 token만 소모하는 역할이다. PPIFparse 호출하지 않는다.
                    ulpCOMPEraseBN4MacroText( sTmpExpBuf , ID_TRUE );
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_ELIF, PP_IF_IGNORE );
                    break;

                case PP_IF_FALSE :
                    ulpCOMPEraseBN4MacroText( sTmpExpBuf , ID_TRUE );

                    gUlpPPIFbufptr = sTmpExpBuf;
                    gUlpPPIFbuflim = sTmpExpBuf + idlOS::strlen(sTmpExpBuf);

                    if ( PPIFparse( sTmpExpBuf, &sVal ) != 0 )
                    {
                        //error 처리

                        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                         ulpERR_ABORT_COMP_ELIF_Macro_Syntax_Error );
                        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                        COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                    }

                    /* macro 조건문의 경우 참이면 MACRO상태, 거짓이면 MACRO_IFSKIP 상태로
                     * 전이 된다. */
                    if ( sVal != 0 )
                    {
                        gUlpCOMPStartCond = gUlpCOMPPrevCond;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_ELIF, PP_IF_TRUE );
                    }
                    else
                    {
                        gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_ELIF, PP_IF_FALSE );
                    }
                    break;

                default:
                    IDE_ASSERT(0);
            }
        ;}
    break;

  case 275:

/* Line 1455 of yacc.c  */
#line 2657 "ulpCompy.y"
    {
            switch( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpPrevIfStatus() )
            {
                case PP_IF_IGNORE :
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFDEF, PP_IF_IGNORE );
                    break;

                case PP_IF_TRUE :
                    // $<strval>2 를 macro symbol table에 존재하는지 확인한다.
                    if ( gUlpMacroT.ulpMLookup((yyvsp[(2) - (2)].strval)) != NULL )
                    {
                        // 존재한다
                        gUlpCOMPStartCond = gUlpCOMPPrevCond;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFDEF, PP_IF_TRUE );
                    }
                    else
                    {
                        // 존재안한다
                        gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFDEF, PP_IF_FALSE );
                    }
                    break;

                case PP_IF_FALSE :
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFDEF, PP_IF_IGNORE );
                    break;

                default:
                    IDE_ASSERT(0);
            }
        ;}
    break;

  case 276:

/* Line 1455 of yacc.c  */
#line 2698 "ulpCompy.y"
    {
            switch( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpPrevIfStatus() )
            {
                case PP_IF_IGNORE :
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFNDEF, PP_IF_IGNORE );
                    break;

                case PP_IF_TRUE :
                    // $<strval>2 를 macro symbol table에 존재하는지 확인한다.
                    if ( gUlpMacroT.ulpMLookup((yyvsp[(2) - (2)].strval)) != NULL )
                    {
                        // 존재한다
                        gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFNDEF, PP_IF_FALSE );
                    }
                    else
                    {
                        // 존재안한다
                        gUlpCOMPStartCond = gUlpCOMPPrevCond;
                        // if stack manager 에 결과 정보 push
                        gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFNDEF, PP_IF_TRUE );
                    }
                    break;

                case PP_IF_FALSE :
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_IFNDEF, PP_IF_IGNORE );
                    break;

                default:
                    IDE_ASSERT(0);
            }
        ;}
    break;

  case 277:

/* Line 1455 of yacc.c  */
#line 2739 "ulpCompy.y"
    {
            // #else 순서 문법 검사.
            if ( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfCheckGrammar( PP_ELSE )
                 == ID_FALSE )
            {
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_ELSE_Macro_Sequence_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }

            switch( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpPrevIfStatus() )
            {
                case PP_IF_IGNORE :
                case PP_IF_TRUE :
                    gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_ELSE, PP_IF_IGNORE );
                    break;

                case PP_IF_FALSE :
                    gUlpCOMPStartCond = gUlpCOMPPrevCond;
                    // if stack manager 에 결과 정보 push
                    gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpush( PP_ELSE, PP_IF_TRUE );
                    break;

                default:
                    IDE_ASSERT(0);
            }
        ;}
    break;

  case 278:

/* Line 1455 of yacc.c  */
#line 2775 "ulpCompy.y"
    {
            // #endif 순서 문법 검사.
            if ( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfCheckGrammar( PP_ENDIF )
                 == ID_FALSE )
            {
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_ENDIF_Macro_Sequence_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }
            // if stack 을 이전 조건문 까지 pop 한다.
            gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfpop4endif();

            /* BUG-27961 : preprocessor의 중첩 #if처리시 #endif 다음소스 무조건 출력하는 버그  */
            if( gUlpCOMPifstackMgr[gUlpCOMPifstackInd]->ulpIfneedSkip4Endif() == ID_TRUE )
            {
                // 출력 하지마라.
                gUlpCOMPStartCond = CP_ST_MACRO_IF_SKIP;
            }
            else
            {
                // 출력 해라.
                gUlpCOMPStartCond = gUlpCOMPPrevCond;
            }
        ;}
    break;

  case 279:

/* Line 1455 of yacc.c  */
#line 2813 "ulpCompy.y"
    {
        // 내장구문을 comment형태로 쓴다.
        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        // 내장구문 관련 코드생성한다.
        if( gUlpStmttype > S_IGNORE )
        {
            gUlpCodeGen.ulpGenEmSQLFlush( gUlpStmttype, gUlpIsPrintStmt );
        }
        // ulpCodeGen class 의 query buffer 를 초기화한다.
        gUlpCodeGen.ulpGenInitQBuff();
        // ulpCodeGen class 의 mEmSQLInfo 를 초기화한다.
        gUlpCodeGen.ulpClearEmSQLInfo();
        // lexer의 상태를 embedded sql 구문을 파싱하기 이전상태로 되돌린다.
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
        // init variables
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 280:

/* Line 1455 of yacc.c  */
#line 2832 "ulpCompy.y"
    {

        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        if( gUlpStmttype > S_IGNORE )
        {
            gUlpCodeGen.ulpGenEmSQLFlush( gUlpStmttype, gUlpIsPrintStmt );
        }
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
        // init variables
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 281:

/* Line 1455 of yacc.c  */
#line 2847 "ulpCompy.y"
    {

        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        if( gUlpStmttype > S_IGNORE )
        {
            gUlpCodeGen.ulpGenEmSQLFlush( gUlpStmttype, gUlpIsPrintStmt );
        }
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
        // init variables
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 282:

/* Line 1455 of yacc.c  */
#line 2862 "ulpCompy.y"
    {

        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        if( gUlpStmttype > S_IGNORE )
        {
            gUlpCodeGen.ulpGenEmSQLFlush( gUlpStmttype, gUlpIsPrintStmt );
        }
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
        // init variables
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 283:

/* Line 1455 of yacc.c  */
#line 2877 "ulpCompy.y"
    {

        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        if( gUlpStmttype > S_IGNORE )
        {
            gUlpCodeGen.ulpGenEmSQLFlush( gUlpStmttype, gUlpIsPrintStmt );
        }
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 284:

/* Line 1455 of yacc.c  */
#line 2891 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
    ;}
    break;

  case 285:

/* Line 1455 of yacc.c  */
#line 2897 "ulpCompy.y"
    {
        // whenever 구문을 comment로 쓴다.
        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );

        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
    ;}
    break;

  case 286:

/* Line 1455 of yacc.c  */
#line 2906 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        if( gUlpStmttype > S_IGNORE )
        {
            gUlpCodeGen.ulpGenEmSQLFlush( gUlpStmttype, gUlpIsPrintStmt );
        }
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpCOMPStartCond = gUlpCOMPPrevCond;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 287:

/* Line 1455 of yacc.c  */
#line 2920 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        gUlpCodeGen.ulpGenInitQBuff();
        gUlpCodeGen.ulpClearEmSQLInfo();
        gUlpIsPrintStmt = ID_TRUE;
        gUlpStmttype    = S_UNKNOWN;
    ;}
    break;

  case 288:

/* Line 1455 of yacc.c  */
#line 2931 "ulpCompy.y"
    {
        // do nothing
    ;}
    break;

  case 289:

/* Line 1455 of yacc.c  */
#line 2935 "ulpCompy.y"
    {
        if ( idlOS::strlen((yyvsp[(2) - (2)].strval)) > MAX_CONN_NAME_LEN )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Exceed_Max_Connname_Error,
                             (yyvsp[(2) - (2)].strval) );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            gUlpCodeGen.ulpGenEmSQL( GEN_CONNNAME, (void *) (yyvsp[(2) - (2)].strval) );
            gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(2) - (2)].strval) );
            gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(1) - (2)].strval) );
        }

    ;}
    break;

  case 290:

/* Line 1455 of yacc.c  */
#line 2955 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_CONNNAME, (void *) (yyvsp[(2) - (2)].strval) );
        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(2) - (2)].strval) );
        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(1) - (2)].strval) );
    ;}
    break;

  case 291:

/* Line 1455 of yacc.c  */
#line 2973 "ulpCompy.y"
    {
        gUlpStmttype = S_DeclareCur;
    ;}
    break;

  case 292:

/* Line 1455 of yacc.c  */
#line 2977 "ulpCompy.y"
    {
        gUlpStmttype = S_DeclareStmt;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 293:

/* Line 1455 of yacc.c  */
#line 2982 "ulpCompy.y"
    {
        gUlpStmttype = S_Open;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 294:

/* Line 1455 of yacc.c  */
#line 2987 "ulpCompy.y"
    {
        gUlpStmttype = S_Fetch;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 295:

/* Line 1455 of yacc.c  */
#line 2992 "ulpCompy.y"
    {
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 296:

/* Line 1455 of yacc.c  */
#line 2996 "ulpCompy.y"
    {
        gUlpStmttype = S_AutoCommit;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 297:

/* Line 1455 of yacc.c  */
#line 3001 "ulpCompy.y"
    {
        gUlpStmttype = S_Connect;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 298:

/* Line 1455 of yacc.c  */
#line 3006 "ulpCompy.y"
    {
        gUlpStmttype = S_Disconnect;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 299:

/* Line 1455 of yacc.c  */
#line 3011 "ulpCompy.y"
    {
        gUlpStmttype = S_FreeLob;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 300:

/* Line 1455 of yacc.c  */
#line 3029 "ulpCompy.y"
    {
        /* BUG-40939 */
        SChar* sTmpQueryBuf;
        UInt   sCurNameLength = 0;

        sCurNameLength = idlOS::strlen( gUlpCodeGen.ulpGenGetEmSQLInfo()->mCurName );
        sTmpQueryBuf = idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(), 
                                      gUlpCodeGen.ulpGenGetEmSQLInfo()->mCurName ) + sCurNameLength;
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR, 
                                 idlOS::strstr(sTmpQueryBuf, (yyvsp[(2) - (3)].strval)) );
        gUlpIsPrintStmt = ID_TRUE;
    ;}
    break;

  case 301:

/* Line 1455 of yacc.c  */
#line 3042 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (3)].strval) );
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 302:

/* Line 1455 of yacc.c  */
#line 3051 "ulpCompy.y"
    {
        if ( idlOS::strlen((yyvsp[(2) - (7)].strval)) >= MAX_CUR_NAME_LEN)
        {

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Exceed_Max_Cursorname_Error,
                             (yyvsp[(2) - (7)].strval) );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }

        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(2) - (7)].strval) );
    ;}
    break;

  case 303:

/* Line 1455 of yacc.c  */
#line 3069 "ulpCompy.y"
    {
        UInt sValue = SQL_INSENSITIVE;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURSORSENSITIVITY, (void *)&sValue );
  ;}
    break;

  case 304:

/* Line 1455 of yacc.c  */
#line 3074 "ulpCompy.y"
    {
        UInt sValue = SQL_SENSITIVE;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURSORSENSITIVITY, (void *)&sValue );
  ;}
    break;

  case 305:

/* Line 1455 of yacc.c  */
#line 3079 "ulpCompy.y"
    {
        UInt sValue = SQL_INSENSITIVE;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURSORSENSITIVITY, (void *)&sValue );
  ;}
    break;

  case 306:

/* Line 1455 of yacc.c  */
#line 3084 "ulpCompy.y"
    {
        UInt sValue = SQL_INSENSITIVE;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURSORSENSITIVITY, (void *)&sValue );
  ;}
    break;

  case 307:

/* Line 1455 of yacc.c  */
#line 3093 "ulpCompy.y"
    {
        UInt sValue = SQL_NONSCROLLABLE;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURSORSCROLLABLE, (void *) &sValue );
;}
    break;

  case 308:

/* Line 1455 of yacc.c  */
#line 3098 "ulpCompy.y"
    {
        UInt sValue = SQL_SCROLLABLE;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURSORSCROLLABLE, (void *) &sValue );
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "1" );
    ;}
    break;

  case 309:

/* Line 1455 of yacc.c  */
#line 3108 "ulpCompy.y"
    {
      UInt sValue = SQL_CURSOR_HOLD_OFF;
      gUlpCodeGen.ulpGenEmSQL( GEN_CURSORWITHHOLD, (void *) &sValue );
  ;}
    break;

  case 310:

/* Line 1455 of yacc.c  */
#line 3113 "ulpCompy.y"
    {
      UInt sValue = SQL_CURSOR_HOLD_ON;
      gUlpCodeGen.ulpGenEmSQL( GEN_CURSORWITHHOLD, (void *) &sValue );
  ;}
    break;

  case 311:

/* Line 1455 of yacc.c  */
#line 3118 "ulpCompy.y"
    {
      ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                       ulpERR_ABORT_COMP_Not_Supported_WITH_RETURN_Error );
      gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
      COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
  ;}
    break;

  case 312:

/* Line 1455 of yacc.c  */
#line 3125 "ulpCompy.y"
    {
      ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                       ulpERR_ABORT_COMP_Not_Supported_WITH_RETURN_Error );
      gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
      COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
  ;}
    break;

  case 314:

/* Line 1455 of yacc.c  */
#line 3136 "ulpCompy.y"
    {

      ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                       ulpERR_ABORT_COMP_Not_Supported_READ_ONLY_Error );
      gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
      COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
  ;}
    break;

  case 322:

/* Line 1455 of yacc.c  */
#line 3164 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (3)].strval) );
    ;}
    break;

  case 323:

/* Line 1455 of yacc.c  */
#line 3175 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(2) - (2)].strval) );
    ;}
    break;

  case 324:

/* Line 1455 of yacc.c  */
#line 3179 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(2) - (4)].strval) );
    ;}
    break;

  case 325:

/* Line 1455 of yacc.c  */
#line 3184 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(2) - (4)].strval) );
    ;}
    break;

  case 326:

/* Line 1455 of yacc.c  */
#line 3195 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(3) - (5)].strval) );
    ;}
    break;

  case 327:

/* Line 1455 of yacc.c  */
#line 3200 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(3) - (6)].strval) );
    ;}
    break;

  case 332:

/* Line 1455 of yacc.c  */
#line 3214 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "1" /*F_FIRST*/ );
    ;}
    break;

  case 333:

/* Line 1455 of yacc.c  */
#line 3218 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "2" /*F_PRIOR*/ );
    ;}
    break;

  case 334:

/* Line 1455 of yacc.c  */
#line 3222 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "3" /*F_NEXT*/ );
    ;}
    break;

  case 335:

/* Line 1455 of yacc.c  */
#line 3226 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "4" /*F_LAST*/ );
    ;}
    break;

  case 336:

/* Line 1455 of yacc.c  */
#line 3230 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "5" /*F_CURRENT*/ );
    ;}
    break;

  case 337:

/* Line 1455 of yacc.c  */
#line 3234 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "6" /*F_RELATIVE*/ );
    ;}
    break;

  case 338:

/* Line 1455 of yacc.c  */
#line 3238 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SCROLLCUR, (void *) "7" /*F_ABSOLUTE*/ );
    ;}
    break;

  case 339:

/* Line 1455 of yacc.c  */
#line 3245 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) (yyvsp[(1) - (1)].strval) );
    ;}
    break;

  case 340:

/* Line 1455 of yacc.c  */
#line 3249 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) (yyvsp[(2) - (2)].strval) );
    ;}
    break;

  case 341:

/* Line 1455 of yacc.c  */
#line 3253 "ulpCompy.y"
    {
        SChar sTmpStr[MAX_NUMBER_LEN];
        idlOS::snprintf( sTmpStr, MAX_NUMBER_LEN ,"-%s", (yyvsp[(2) - (2)].strval) );
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) sTmpStr );
    ;}
    break;

  case 342:

/* Line 1455 of yacc.c  */
#line 3267 "ulpCompy.y"
    {
        gUlpStmttype = S_CloseRel;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(3) - (3)].strval) );
    ;}
    break;

  case 343:

/* Line 1455 of yacc.c  */
#line 3272 "ulpCompy.y"
    {
        gUlpStmttype = S_Close;
        gUlpCodeGen.ulpGenEmSQL( GEN_CURNAME, (void *) (yyvsp[(2) - (2)].strval) );
    ;}
    break;

  case 344:

/* Line 1455 of yacc.c  */
#line 3284 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "1" /*ON*/);
    ;}
    break;

  case 345:

/* Line 1455 of yacc.c  */
#line 3288 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "0" /*OFF*/);
    ;}
    break;

  case 346:

/* Line 1455 of yacc.c  */
#line 3299 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // User name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (5)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(2) - (5)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        // Password name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(5) - (5)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(5) - (5)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        gUlpCodeGen.ulpIncHostVarNum( 2 );
    ;}
    break;

  case 347:

/* Line 1455 of yacc.c  */
#line 3323 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // User name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (7)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(2) - (7)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        // Password name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(5) - (7)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(5) - (7)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        /* using open :drivername */
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(7) - (7)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        // driver name이라고 표시함.
        //sSymNode -> mMoreInfo = 1;
        //gUlpCodeGen.ulpGenAddHostVarList( sSymNode );

        gUlpCodeGen.ulpIncHostVarNum( 2 );
    ;}
    break;

  case 348:

/* Line 1455 of yacc.c  */
#line 3357 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // User name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (7)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(2) - (7)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        // Password name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(5) - (7)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(5) - (7)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);


        /* using :conn_opt1 */
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(7) - (7)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        // driver name이라고 표시함.
        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(7) - (7)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        gUlpCodeGen.ulpIncHostVarNum( 3 );
    ;}
    break;

  case 349:

/* Line 1455 of yacc.c  */
#line 3392 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // User name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(2) - (9)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        // Password name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(5) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(5) - (9)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        /* using :conn_opt1, :conn_opt2 */
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(7) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(7) - (9)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);


        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(9) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(9) - (9)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        gUlpCodeGen.ulpIncHostVarNum( 4 );
    ;}
    break;

  case 350:

/* Line 1455 of yacc.c  */
#line 3434 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // User name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (11)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(2) - (11)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        // Password name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(5) - (11)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(5) - (11)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        /* using :conn_opt1, :conn_opt2 open :drivername */
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(7) - (11)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(7) - (11)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(9) - (11)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(9) - (11)].strval)+1, sSymNode ,
                                          gUlpIndName, NULL, NULL, HV_IN_TYPE);

        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(11) - (11)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        // driver name이라고 표시함.
        //sSymNode -> mMoreInfo = 1;
        //gUlpCodeGen.ulpGenAddHostVarList( sSymNode );

        gUlpCodeGen.ulpIncHostVarNum( 4 );
    ;}
    break;

  case 351:

/* Line 1455 of yacc.c  */
#line 3484 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // User name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(2) - (9)].strval)+1, sSymNode , gUlpIndName,
                                          NULL, NULL, HV_IN_TYPE);

        // Password name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(5) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(5) - (9)].strval)+1, sSymNode , gUlpIndName, NULL,
                                          NULL, HV_IN_TYPE);

        /* using :conn_opt1 open :drivername */
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(7) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(7) - (9)].strval)+1, sSymNode , gUlpIndName, NULL,
                                          NULL, HV_IN_TYPE);

        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(9) - (9)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        // driver name이라고 표시함.
        //sSymNode -> mMoreInfo = 1;
        //gUlpCodeGen.ulpGenAddHostVarList( sSymNode );

        gUlpCodeGen.ulpIncHostVarNum( 3 );
    ;}
    break;

  case 353:

/* Line 1455 of yacc.c  */
#line 3541 "ulpCompy.y"
    {

    ;}
    break;

  case 354:

/* Line 1455 of yacc.c  */
#line 3545 "ulpCompy.y"
    {

    ;}
    break;

  case 355:

/* Line 1455 of yacc.c  */
#line 3559 "ulpCompy.y"
    {
        gUlpStmttype    = S_IGNORE;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 356:

/* Line 1455 of yacc.c  */
#line 3564 "ulpCompy.y"
    {
        gUlpStmttype    = S_IGNORE;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 357:

/* Line 1455 of yacc.c  */
#line 3569 "ulpCompy.y"
    {
        gUlpStmttype = S_Prepare;
        gUlpIsPrintStmt = ID_TRUE;
    ;}
    break;

  case 358:

/* Line 1455 of yacc.c  */
#line 3574 "ulpCompy.y"
    {
        gUlpStmttype    = S_IGNORE;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 359:

/* Line 1455 of yacc.c  */
#line 3579 "ulpCompy.y"
    {
        gUlpStmttype    = S_ExecIm;
        gUlpIsPrintStmt = ID_TRUE;
    ;}
    break;

  case 360:

/* Line 1455 of yacc.c  */
#line 3584 "ulpCompy.y"
    {
        gUlpStmttype    = S_ExecDML;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 361:

/* Line 1455 of yacc.c  */
#line 3590 "ulpCompy.y"
    {
        gUlpStmttype    = S_BindVariables;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 362:

/* Line 1455 of yacc.c  */
#line 3595 "ulpCompy.y"
    {
        gUlpStmttype    = S_SetArraySize;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 363:

/* Line 1455 of yacc.c  */
#line 3600 "ulpCompy.y"
    {
        gUlpStmttype    = S_SelectList;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 367:

/* Line 1455 of yacc.c  */
#line 3614 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("MAX", (yyvsp[(2) - (3)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 370:

/* Line 1455 of yacc.c  */
#line 3634 "ulpCompy.y"
    {
        SChar sTmpStr[MAX_HOSTVAR_NAME_SIZE];
        ulpSymTElement *sSymNode;

        if ( (sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (2)].strval)+1, gUlpCurDepth )) == NULL )
        {
            //host 변수 못찾는 error
        }

        if( sSymNode != NULL )
        {
            if ( (sSymNode->mType == H_VARCHAR) ||
                 (sSymNode->mType == H_NVARCHAR) )
            {
                idlOS::snprintf( sTmpStr, MAX_HOSTVAR_NAME_SIZE,
                                "%s.arr",
                                (yyvsp[(2) - (2)].strval)+1 );
                gUlpCodeGen.ulpGenEmSQL( GEN_QUERYHV, (void *) sTmpStr );
            }
            else
            {
                gUlpCodeGen.ulpGenEmSQL( GEN_QUERYHV, (yyvsp[(2) - (2)].strval)+1 );
            }
        }
        else
        {
            gUlpCodeGen.ulpGenEmSQL( GEN_QUERYHV, (yyvsp[(2) - (2)].strval)+1 );
        }
    ;}
    break;

  case 371:

/* Line 1455 of yacc.c  */
#line 3664 "ulpCompy.y"
    {
        /* BUG-40939 */
        SChar* sTmpQueryBuf;
        UInt   sStmtNameLength = 0;
        sStmtNameLength = idlOS::strlen( gUlpCodeGen.ulpGenGetEmSQLInfo()->mStmtName );
        sTmpQueryBuf = idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                      gUlpCodeGen.ulpGenGetEmSQLInfo()->mStmtName ) + sStmtNameLength;
                                      
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( sTmpQueryBuf, (yyvsp[(2) - (2)].strval)) );
    ;}
    break;

  case 372:

/* Line 1455 of yacc.c  */
#line 3676 "ulpCompy.y"
    {
        /* BUG-40939 */
        SChar* sTmpQueryBuf;
        SInt   sStmtNameLength = 0;
        sStmtNameLength = idlOS::strlen( gUlpCodeGen.ulpGenGetEmSQLInfo()->mStmtName );
        sTmpQueryBuf = idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                      gUlpCodeGen.ulpGenGetEmSQLInfo()->mStmtName ) + sStmtNameLength;
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( sTmpQueryBuf, (yyvsp[(2) - (2)].strval)) );
    ;}
    break;

  case 373:

/* Line 1455 of yacc.c  */
#line 3690 "ulpCompy.y"
    {
        if ( idlOS::strlen((yyvsp[(2) - (3)].strval)) >= MAX_STMT_NAME_LEN )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Exceed_Max_Stmtname_Error,
                             (yyvsp[(2) - (3)].strval) );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (3)].strval) );
    ;}
    break;

  case 376:

/* Line 1455 of yacc.c  */
#line 3729 "ulpCompy.y"
    {
        SChar sTmpStr[MAX_HOSTVAR_NAME_SIZE];
        ulpSymTElement *sSymNode;

        if ( (sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (2)].strval)+1, gUlpCurDepth )) == NULL )
        {
            //don't report error
        }

        if ( sSymNode != NULL )
        {
            if ( (sSymNode->mType == H_VARCHAR) ||
                 (sSymNode->mType == H_NVARCHAR) )
            {
                idlOS::snprintf( sTmpStr, MAX_HOSTVAR_NAME_SIZE,
                                 "%s.arr",
                                 (yyvsp[(2) - (2)].strval)+1 );
                gUlpCodeGen.ulpGenEmSQL( GEN_QUERYHV, (void *) sTmpStr );
            }
            else
            {
                gUlpCodeGen.ulpGenEmSQL( GEN_QUERYHV, (yyvsp[(2) - (2)].strval)+1 );
            }
        }
        else
        {
            gUlpCodeGen.ulpGenEmSQL( GEN_QUERYHV, (yyvsp[(2) - (2)].strval)+1 );
        }
    ;}
    break;

  case 377:

/* Line 1455 of yacc.c  */
#line 3759 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(2) - (2)].strval))
                               );
    ;}
    break;

  case 378:

/* Line 1455 of yacc.c  */
#line 3766 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(2) - (2)].strval))
                               );
    ;}
    break;

  case 380:

/* Line 1455 of yacc.c  */
#line 3780 "ulpCompy.y"
    {
      gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (2)].strval) );
  ;}
    break;

  case 381:

/* Line 1455 of yacc.c  */
#line 3784 "ulpCompy.y"
    {
      gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(3) - (5)].strval) );
  ;}
    break;

  case 382:

/* Line 1455 of yacc.c  */
#line 3788 "ulpCompy.y"
    {
      gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (4)].strval) );
  ;}
    break;

  case 383:

/* Line 1455 of yacc.c  */
#line 3792 "ulpCompy.y"
    {
      gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (4)].strval) );
  ;}
    break;

  case 384:

/* Line 1455 of yacc.c  */
#line 3800 "ulpCompy.y"
    {
      gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(5) - (7)].strval) );
  ;}
    break;

  case 385:

/* Line 1455 of yacc.c  */
#line 3807 "ulpCompy.y"
    {
      gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(2) - (3)].strval) );
  ;}
    break;

  case 386:

/* Line 1455 of yacc.c  */
#line 3815 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("LIST", (yyvsp[(3) - (7)].strval), 4) != 0)
      {
          // error 처리
          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
      else
      {
          gUlpCodeGen.ulpGenEmSQL( GEN_STMTNAME, (void *) (yyvsp[(5) - (7)].strval) );
      }
  ;}
    break;

  case 387:

/* Line 1455 of yacc.c  */
#line 3843 "ulpCompy.y"
    {
        gUlpStmttype    = S_DirectOTH;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );

    ;}
    break;

  case 388:

/* Line 1455 of yacc.c  */
#line 3850 "ulpCompy.y"
    {
        gUlpStmttype    = S_DirectOTH;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );
    ;}
    break;

  case 389:

/* Line 1455 of yacc.c  */
#line 3856 "ulpCompy.y"
    {
        gUlpStmttype    = S_DirectOTH;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );
    ;}
    break;

  case 390:

/* Line 1455 of yacc.c  */
#line 3862 "ulpCompy.y"
    {
        idBool sTrue;
        sTrue = ID_TRUE;
        gUlpStmttype    = S_DirectPSM;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(3) - (6)].strval))
                               );
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );
        gUlpCodeGen.ulpGenEmSQL( GEN_PSMEXEC, (void *) &sTrue );
    ;}
    break;

  case 391:

/* Line 1455 of yacc.c  */
#line 3876 "ulpCompy.y"
    {
        idBool sTrue;
        sTrue = ID_TRUE;
        gUlpStmttype    = S_DirectPSM;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(3) - (6)].strval))
                               );
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );
        gUlpCodeGen.ulpGenCutQueryTail4PSM( ';' );
        gUlpCodeGen.ulpGenEmSQL( GEN_PSMEXEC, (void *) &sTrue );
    ;}
    break;

  case 393:

/* Line 1455 of yacc.c  */
#line 3904 "ulpCompy.y"
    {
        gUlpStmttype    = S_Free;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 394:

/* Line 1455 of yacc.c  */
#line 3909 "ulpCompy.y"
    {
        gUlpStmttype    = S_Batch;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 395:

/* Line 1455 of yacc.c  */
#line 3914 "ulpCompy.y"
    {
        gUlpStmttype    = S_Batch;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 396:

/* Line 1455 of yacc.c  */
#line 3920 "ulpCompy.y"
    {
        gUlpStmttype = S_AutoCommit;
        gUlpIsPrintStmt = ID_FALSE;
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "1" /*ON*/);
    ;}
    break;

  case 397:

/* Line 1455 of yacc.c  */
#line 3927 "ulpCompy.y"
    {
        gUlpStmttype = S_AutoCommit;
        gUlpIsPrintStmt = ID_FALSE;
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "0" /*OFF*/);
    ;}
    break;

  case 398:

/* Line 1455 of yacc.c  */
#line 3934 "ulpCompy.y"
    {
        if(idlOS::strcasecmp("DEFAULT_DATE_FORMAT", (yyvsp[(4) - (6)].strval)) != 0 &&
           idlOS::strcasecmp("DATE_FORMAT", (yyvsp[(4) - (6)].strval)) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }

        gUlpStmttype = S_AlterSession;
        gUlpIsPrintStmt = ID_FALSE;
        gUlpCodeGen.ulpGenEmSQL( GEN_EXTRASTRINFO, (yyvsp[(6) - (6)].strval) );
    ;}
    break;

  case 399:

/* Line 1455 of yacc.c  */
#line 3951 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // failover var. name
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(3) - (3)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            // error 처리.
        }
        else
        {
            gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(3) - (3)].strval)+1, sSymNode , gUlpIndName, NULL,
                                              NULL, HV_IN_TYPE);
        }

        gUlpCodeGen.ulpIncHostVarNum( 1 );

        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "1" /*SET*/);
        gUlpStmttype = S_FailOver;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 400:

/* Line 1455 of yacc.c  */
#line 3972 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "0" /*UNSET*/);
        gUlpStmttype = S_FailOver;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 401:

/* Line 1455 of yacc.c  */
#line 3988 "ulpCompy.y"
    {
        idBool sTrue = ID_TRUE;
        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        gUlpCodeGen.ulpGenEmSQL( GEN_MT, (void *)&sTrue );
    ;}
    break;

  case 402:

/* Line 1455 of yacc.c  */
#line 3994 "ulpCompy.y"
    {
        idBool sFalse = ID_FALSE;
        gUlpCodeGen.ulpGenComment( gUlpCodeGen.ulpGetQueryBuf() );
        gUlpCodeGen.ulpGenEmSQL( GEN_MT, (void *)&sFalse );
  ;}
    break;

  case 403:

/* Line 1455 of yacc.c  */
#line 4010 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_SQLERROR,
                                       GEN_WHEN_CONT,
                                       NULL );
    ;}
    break;

  case 404:

/* Line 1455 of yacc.c  */
#line 4017 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_SQLERROR,
                                       GEN_WHEN_GOTO,
                                       (yyvsp[(4) - (4)].strval) );
    ;}
    break;

  case 405:

/* Line 1455 of yacc.c  */
#line 4024 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_SQLERROR,
                                       GEN_WHEN_DO_BREAK,
                                       NULL );
    ;}
    break;

  case 406:

/* Line 1455 of yacc.c  */
#line 4031 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_SQLERROR,
                                       GEN_WHEN_DO_CONT,
                                       NULL );
    ;}
    break;

  case 407:

/* Line 1455 of yacc.c  */
#line 4038 "ulpCompy.y"
    {
        SChar  sTmpStr[MAX_EXPR_LEN];

        idlOS::snprintf( sTmpStr, MAX_EXPR_LEN , "%s(", (yyvsp[(4) - (5)].strval) );
        ulpCOMPWheneverFunc( sTmpStr );
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_SQLERROR,
                                       GEN_WHEN_DO_FUNC,
                                       sTmpStr );
    ;}
    break;

  case 408:

/* Line 1455 of yacc.c  */
#line 4049 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_SQLERROR,
                                       GEN_WHEN_STOP,
                                       NULL );
    ;}
    break;

  case 409:

/* Line 1455 of yacc.c  */
#line 4056 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_NOTFOUND,
                                       GEN_WHEN_CONT,
                                       NULL );
    ;}
    break;

  case 410:

/* Line 1455 of yacc.c  */
#line 4063 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_NOTFOUND,
                                       GEN_WHEN_GOTO,
                                       (yyvsp[(5) - (5)].strval) );
    ;}
    break;

  case 411:

/* Line 1455 of yacc.c  */
#line 4070 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_NOTFOUND,
                                       GEN_WHEN_DO_BREAK,
                                       NULL );
    ;}
    break;

  case 412:

/* Line 1455 of yacc.c  */
#line 4077 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth, 
                                       GEN_WHEN_NOTFOUND,
                                       GEN_WHEN_DO_CONT,
                                       NULL );
    ;}
    break;

  case 413:

/* Line 1455 of yacc.c  */
#line 4084 "ulpCompy.y"
    {
        SChar  sTmpStr[MAX_EXPR_LEN];

        idlOS::snprintf( sTmpStr, MAX_EXPR_LEN , "%s(", (yyvsp[(5) - (6)].strval) );
        ulpCOMPWheneverFunc( sTmpStr );
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_NOTFOUND,
                                       GEN_WHEN_DO_FUNC,
                                       sTmpStr );
    ;}
    break;

  case 414:

/* Line 1455 of yacc.c  */
#line 4095 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenSetWhenever( gUlpCurDepth,
                                       GEN_WHEN_NOTFOUND,
                                       GEN_WHEN_STOP,
                                       NULL );
    ;}
    break;

  case 416:

/* Line 1455 of yacc.c  */
#line 4107 "ulpCompy.y"
    {
        gUlpStmttype    = S_IGNORE;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 417:

/* Line 1455 of yacc.c  */
#line 4114 "ulpCompy.y"
    {
        gUlpSharedPtrPrevCond  = gUlpCOMPPrevCond;
        gUlpCOMPStartCond = CP_ST_C;
        idlOS::strcpy ( gUlpCodeGen.ulpGetSharedPtrName(), (yyvsp[(5) - (6)].strval) );
        gUlpParseInfo.mIsSharedPtr = ID_TRUE;

    ;}
    break;

  case 418:

/* Line 1455 of yacc.c  */
#line 4122 "ulpCompy.y"
    {
        gUlpCOMPStartCond = gUlpSharedPtrPrevCond;
        gUlpParseInfo.mIsSharedPtr = ID_FALSE;
        gUlpCodeGen.ulpClearSharedPtrInfo();
    ;}
    break;

  case 419:

/* Line 1455 of yacc.c  */
#line 4139 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectOTH;
        gUlpIsPrintStmt = ID_TRUE;
    ;}
    break;

  case 420:

/* Line 1455 of yacc.c  */
#line 4145 "ulpCompy.y"
    {
        gUlpIsPrintStmt = ID_TRUE;
    ;}
    break;

  case 421:

/* Line 1455 of yacc.c  */
#line 4149 "ulpCompy.y"
    {
        gUlpStmttype = S_Commit;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 422:

/* Line 1455 of yacc.c  */
#line 4154 "ulpCompy.y"
    {
    ;}
    break;

  case 494:

/* Line 1455 of yacc.c  */
#line 4255 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(2) - (2)].strval))
                               );

    ;}
    break;

  case 495:

/* Line 1455 of yacc.c  */
#line 4266 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (1)].strval))
                               );
    ;}
    break;

  case 496:

/* Line 1455 of yacc.c  */
#line 4276 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(2) - (2)].strval))
                               );

    ;}
    break;

  case 497:

/* Line 1455 of yacc.c  */
#line 4287 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (1)].strval))
                               );

    ;}
    break;

  case 498:

/* Line 1455 of yacc.c  */
#line 4298 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(2) - (2)].strval))
                               );

    ;}
    break;

  case 499:

/* Line 1455 of yacc.c  */
#line 4309 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (1)].strval))
                               );

    ;}
    break;

  case 500:

/* Line 1455 of yacc.c  */
#line 4320 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (1)].strval))
                               );

    ;}
    break;

  case 501:

/* Line 1455 of yacc.c  */
#line 4331 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (1)].strval))
                               );

    ;}
    break;

  case 502:

/* Line 1455 of yacc.c  */
#line 4342 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectSEL;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (3)].strval))
                               );

    ;}
    break;

  case 503:

/* Line 1455 of yacc.c  */
#line 4353 "ulpCompy.y"
    {
        //is_select = sesTRUE;
        gUlpStmttype = S_DirectSEL;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (3)].strval))
                               );
    ;}
    break;

  case 504:

/* Line 1455 of yacc.c  */
#line 4364 "ulpCompy.y"
    {
        gUlpStmttype = S_DirectDML;

        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (1)].strval))
                               );
    ;}
    break;

  case 508:

/* Line 1455 of yacc.c  */
#line 4382 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_STATUSPTR, (yyvsp[(2) - (4)].strval)+1 );
        gUlpCodeGen.ulpGenEmSQL( GEN_ERRCODEPTR, (yyvsp[(4) - (4)].strval)+1 );
    ;}
    break;

  case 509:

/* Line 1455 of yacc.c  */
#line 4390 "ulpCompy.y"
    {
        SInt sNum;

        sNum = idlOS::atoi((yyvsp[(2) - (2)].strval));

        if ( sNum < 1 )
        {
            //The count of FOR clause must be greater than zero
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_FOR_iternum_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            gUlpCodeGen.ulpGenEmSQL( GEN_ITERS, (void *) (yyvsp[(2) - (2)].strval) );
        }
    ;}
    break;

  case 510:

/* Line 1455 of yacc.c  */
#line 4411 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (2)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
        }

        gUlpCodeGen.ulpGenEmSQL( GEN_ITERS, (yyvsp[(2) - (2)].strval)+1 );
    ;}
    break;

  case 511:

/* Line 1455 of yacc.c  */
#line 4422 "ulpCompy.y"
    {

        if(idlOS::strncasecmp("ATOMIC", (yyvsp[(1) - (3)].strval), 6) == 0)
        {
            if ( idlOS::atoi((yyvsp[(3) - (3)].strval)) < 1 )
            {
                //The count of FOR clause must be greater than zero
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_FOR_iternum_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }
            else
            {
                gUlpCodeGen.ulpGenEmSQL( GEN_ITERS, (void *) (yyvsp[(3) - (3)].strval) );
                gUlpCodeGen.ulpGenEmSQL( GEN_ATOMIC, (void *) "1" );
            }
        }
        else
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 512:

/* Line 1455 of yacc.c  */
#line 4453 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        if( idlOS::strncasecmp("ATOMIC", (yyvsp[(1) - (3)].strval), 6) == 0 )
        {
            if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(3) - (3)].strval)+1, gUlpCurDepth ) ) == NULL )
            {
                //host 변수 못찾는 error
            }

            gUlpCodeGen.ulpGenEmSQL( GEN_ITERS, (yyvsp[(3) - (3)].strval)+1 );

            gUlpCodeGen.ulpGenEmSQL( GEN_ATOMIC, (void *) "1" );
        }
        else
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 513:

/* Line 1455 of yacc.c  */
#line 4481 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "0" );
    ;}
    break;

  case 514:

/* Line 1455 of yacc.c  */
#line 4485 "ulpCompy.y"
    {
        // release 구문이 오면 disconnect 해야한다.
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "1" );
    ;}
    break;

  case 515:

/* Line 1455 of yacc.c  */
#line 4493 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "2" );
    ;}
    break;

  case 516:

/* Line 1455 of yacc.c  */
#line 4497 "ulpCompy.y"
    {
        // release 구문이 오면 disconnect 해야한다.
        gUlpCodeGen.ulpGenEmSQL( GEN_SQLINFO, (void *) "3" );
        // 나중에 rollback 구문을 comment로 출력할때 release 토큰은 제거됨을 주의하자.
        gUlpCodeGen.ulpGenCutQueryTail( (yyvsp[(2) - (2)].strval) );
    ;}
    break;

  case 583:

/* Line 1455 of yacc.c  */
#line 4592 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("EAGER", (yyvsp[(6) - (6)].strval), 5) != 0 &&
           idlOS::strncasecmp("LAZY", (yyvsp[(6) - (6)].strval), 4) != 0 &&
           idlOS::strncasecmp("ACKED", (yyvsp[(6) - (6)].strval), 5) != 0 &&
           idlOS::strncasecmp("NONE", (yyvsp[(6) - (6)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 584:

/* Line 1455 of yacc.c  */
#line 4608 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("EXPLAIN", (yyvsp[(4) - (7)].strval), 7) != 0 ||
           idlOS::strncasecmp("PLAN", (yyvsp[(5) - (7)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 585:

/* Line 1455 of yacc.c  */
#line 4622 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("EXPLAIN", (yyvsp[(4) - (7)].strval), 7) != 0 ||
           idlOS::strncasecmp("PLAN", (yyvsp[(5) - (7)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 586:

/* Line 1455 of yacc.c  */
#line 4636 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("EXPLAIN", (yyvsp[(4) - (7)].strval), 7) != 0 ||
           idlOS::strncasecmp("PLAN", (yyvsp[(5) - (7)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 588:

/* Line 1455 of yacc.c  */
#line 4652 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("STACK", (yyvsp[(4) - (7)].strval), 5) != 0 ||
           idlOS::strncasecmp("SIZE", (yyvsp[(5) - (7)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 590:

/* Line 1455 of yacc.c  */
#line 4672 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (3)].strval), 6) != 0 ||
           idlOS::strncasecmp("CHECKPOINT", (yyvsp[(3) - (3)].strval), 10) != 0 &&
           idlOS::strncasecmp("REORGANIZE", (yyvsp[(3) - (3)].strval), 10) != 0 &&
           idlOS::strncasecmp("VERIFY", (yyvsp[(3) - (3)].strval), 6) != 0 &&
           idlOS::strncasecmp("COMPACT", (yyvsp[(3) - (3)].strval), 7) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        if(idlOS::strncasecmp("COMPACT", (yyvsp[(3) - (3)].strval), 7) == 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Not_Supported_ALTER_COMPACT_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 591:

/* Line 1455 of yacc.c  */
#line 4698 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (4)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            if(idlOS::strncasecmp("MEMORY", (yyvsp[(3) - (4)].strval), 6) == 0 &&
               idlOS::strncasecmp("COMPACT", (yyvsp[(4) - (4)].strval), 7) == 0)
            {
                // Nothing to do 
            }
            else if(idlOS::strncasecmp("SWITCH", (yyvsp[(3) - (4)].strval), 6) == 0 &&
                    idlOS::strncasecmp("LOGFILE", (yyvsp[(4) - (4)].strval), 7) == 0)
            {
                // Nothing to do 
            }
            else
            {
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_Unterminated_String_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }
        }
    ;}
    break;

  case 592:

/* Line 1455 of yacc.c  */
#line 4732 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (5)].strval), 6) != 0 ||
           idlOS::strncasecmp("LOG", (yyvsp[(4) - (5)].strval), 3) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 593:

/* Line 1455 of yacc.c  */
#line 4746 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (6)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 594:

/* Line 1455 of yacc.c  */
#line 4759 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (7)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 595:

/* Line 1455 of yacc.c  */
#line 4772 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (6)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 596:

/* Line 1455 of yacc.c  */
#line 4785 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (6)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 597:

/* Line 1455 of yacc.c  */
#line 4798 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (5)].strval), 6) != 0)
        if(idlOS::strncasecmp("RELOAD", (yyvsp[(3) - (5)].strval), 6) != 0 ||
           idlOS::strncasecmp("LIST", (yyvsp[(5) - (5)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 599:

/* Line 1455 of yacc.c  */
#line 4816 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("STOP", (yyvsp[(1) - (1)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 602:

/* Line 1455 of yacc.c  */
#line 4839 "ulpCompy.y"
    {
        gUlpStmttype    = S_Commit;
        gUlpIsPrintStmt = ID_FALSE;
    ;}
    break;

  case 603:

/* Line 1455 of yacc.c  */
#line 4844 "ulpCompy.y"
    {
        gUlpStmttype    = S_DirectRB;
        gUlpIsPrintStmt = ID_TRUE;
        gUlpCodeGen.ulpGenEmSQL( GEN_QUERYSTR,
                                 idlOS::strstr( gUlpCodeGen.ulpGetQueryBuf(),
                                                (yyvsp[(1) - (5)].strval))
                               );
    ;}
    break;

  case 606:

/* Line 1455 of yacc.c  */
#line 4861 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("TRANSACTION", (yyvsp[(2) - (3)].strval), 11) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 607:

/* Line 1455 of yacc.c  */
#line 4873 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("TRANSACTION", (yyvsp[(4) - (5)].strval), 11) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 608:

/* Line 1455 of yacc.c  */
#line 4889 "ulpCompy.y"
    {
        if ( idlOS::strncasecmp( "FORCE", (yyvsp[(3) - (5)].strval), 5 ) != 0 )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 609:

/* Line 1455 of yacc.c  */
#line 4905 "ulpCompy.y"
    {
        if ( idlOS::strncasecmp( "FORCE", (yyvsp[(3) - (5)].strval), 5 ) != 0 )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 612:

/* Line 1455 of yacc.c  */
#line 4925 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("COMMITTED", (yyvsp[(4) - (4)].strval), 9) != 0 &&
           idlOS::strncasecmp("UNCOMMITTED", (yyvsp[(4) - (4)].strval), 11) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 613:

/* Line 1455 of yacc.c  */
#line 4939 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("REPEATABLE", (yyvsp[(3) - (4)].strval), 10) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 614:

/* Line 1455 of yacc.c  */
#line 4952 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SERIALIZABLE", (yyvsp[(3) - (3)].strval), 12) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 653:

/* Line 1455 of yacc.c  */
#line 5080 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYSTEM", (yyvsp[(2) - (2)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 705:

/* Line 1455 of yacc.c  */
#line 5148 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("JOB", (yyvsp[(3) - (3)].strval), 3) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 706:

/* Line 1455 of yacc.c  */
#line 5160 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("JOB", (yyvsp[(3) - (3)].strval), 3) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 707:

/* Line 1455 of yacc.c  */
#line 5172 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("JOB", (yyvsp[(3) - (3)].strval), 3) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 735:

/* Line 1455 of yacc.c  */
#line 5247 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("FORCE", (yyvsp[(1) - (1)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 743:

/* Line 1455 of yacc.c  */
#line 5298 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("HOST", (yyvsp[(5) - (6)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 744:

/* Line 1455 of yacc.c  */
#line 5311 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("HOST", (yyvsp[(5) - (6)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 745:

/* Line 1455 of yacc.c  */
#line 5324 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("HOST", (yyvsp[(5) - (6)].strval), 4) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 747:

/* Line 1455 of yacc.c  */
#line 5342 "ulpCompy.y"
    {
        if ( ( idlOS::strncasecmp("RECOVERY", (yyvsp[(5) - (6)].strval), 8 ) != 0 ) &&
             ( idlOS::strncasecmp("GAPLESS", (yyvsp[(5) - (6)].strval), 7 ) != 0 ) &&
             ( idlOS::strncasecmp("GROUPING", (yyvsp[(5) - (6)].strval), 8 ) != 0 ) )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 754:

/* Line 1455 of yacc.c  */
#line 5373 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYNC", (yyvsp[(4) - (5)].strval), 4) != 0 &&
           idlOS::strncasecmp("QUICKSTART", (yyvsp[(4) - (5)].strval), 10) != 0 &&
           idlOS::strncasecmp("STOP", (yyvsp[(4) - (5)].strval), 4) != 0 &&
           idlOS::strncasecmp("RESET", (yyvsp[(4) - (5)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 755:

/* Line 1455 of yacc.c  */
#line 5390 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SYNC", (yyvsp[(4) - (6)].strval), 4) != 0 &&
           idlOS::strncasecmp("QUICKSTART", (yyvsp[(4) - (6)].strval), 10) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 758:

/* Line 1455 of yacc.c  */
#line 5409 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("OPTIONS", (yyvsp[(1) - (2)].strval), 7) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 761:

/* Line 1455 of yacc.c  */
#line 5429 "ulpCompy.y"
    {
        if ( ( idlOS::strncasecmp("RECOVERY", (yyvsp[(1) - (1)].strval), 8 ) != 0 ) &&
             ( idlOS::strncasecmp("GAPLESS", (yyvsp[(1) - (1)].strval), 7 ) != 0 ) &&
             ( idlOS::strncasecmp("GROUPING", (yyvsp[(1) - (1)].strval), 8 ) != 0 ) )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 766:

/* Line 1455 of yacc.c  */
#line 5453 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("LAZY", (yyvsp[(1) - (1)].strval), 4) != 0 &&
           idlOS::strncasecmp("EAGER", (yyvsp[(1) - (1)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 770:

/* Line 1455 of yacc.c  */
#line 5475 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("UNIX_DOMAIN", (yyvsp[(1) - (1)].strval), 11) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 775:

/* Line 1455 of yacc.c  */
#line 5500 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("ANALYSIS", (yyvsp[(2) - (2)].strval), 8) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 777:

/* Line 1455 of yacc.c  */
#line 5516 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("MASTER", (yyvsp[(2) - (2)].strval), 6) != 0 &&
           idlOS::strncasecmp("SLAVE", (yyvsp[(2) - (2)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 789:

/* Line 1455 of yacc.c  */
#line 5554 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("RETRY", (yyvsp[(1) - (1)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 798:

/* Line 1455 of yacc.c  */
#line 5586 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("RETRY", (yyvsp[(1) - (1)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 799:

/* Line 1455 of yacc.c  */
#line 5599 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SN", (yyvsp[(2) - (5)].strval), 2) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 830:

/* Line 1455 of yacc.c  */
#line 5702 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("INCREMENT", (yyvsp[(1) - (3)].strval), 9) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 831:

/* Line 1455 of yacc.c  */
#line 5715 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("INCREMENT", (yyvsp[(1) - (4)].strval), 9) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 832:

/* Line 1455 of yacc.c  */
#line 5730 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("CACHE", (yyvsp[(1) - (2)].strval), 5) != 0 &&
           idlOS::strncasecmp("MAXVALUE", (yyvsp[(1) - (2)].strval), 8) != 0 &&
           idlOS::strncasecmp("MINVALUE", (yyvsp[(1) - (2)].strval), 8) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 833:

/* Line 1455 of yacc.c  */
#line 5744 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("MAXVALUE", (yyvsp[(1) - (3)].strval), 8) != 0 &&
           idlOS::strncasecmp("MINVALUE", (yyvsp[(1) - (3)].strval), 8) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 834:

/* Line 1455 of yacc.c  */
#line 5760 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("NOCACHE", (yyvsp[(1) - (1)].strval), 7) != 0 &&
           idlOS::strncasecmp("NOMAXVALUE", (yyvsp[(1) - (1)].strval), 10) != 0 &&
           idlOS::strncasecmp("NOMINVALUE", (yyvsp[(1) - (1)].strval), 10) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 847:

/* Line 1455 of yacc.c  */
#line 5809 "ulpCompy.y"
    {
        if ( ( idlOS::strncasecmp("COMPACT", (yyvsp[(4) - (5)].strval), 7) != 0 ) &&
             ( idlOS::strncasecmp("AGING", (yyvsp[(4) - (5)].strval), 5) != 0 ) &&
             ( idlOS::strncasecmp("TOUCH", (yyvsp[(4) - (5)].strval), 5) != 0 ) )
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 919:

/* Line 1455 of yacc.c  */
#line 6018 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("INDEXTYPE", (yyvsp[(1) - (3)].strval), 9) != 0 ||
           idlOS::strncasecmp("BTREE", (yyvsp[(3) - (3)].strval), 5) != 0 &&
           idlOS::strncasecmp("RTREE", (yyvsp[(3) - (3)].strval), 5) != 0 &&
           // Altibase Spatio-Temporal DBMS
           idlOS::strncasecmp("TDRTREE", (yyvsp[(3) - (3)].strval), 7) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 921:

/* Line 1455 of yacc.c  */
#line 6038 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("PERSISTENT", (yyvsp[(2) - (4)].strval), 10) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 922:

/* Line 1455 of yacc.c  */
#line 6050 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("PERSISTENT", (yyvsp[(2) - (4)].strval), 10) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 967:

/* Line 1455 of yacc.c  */
#line 6184 "ulpCompy.y"
    {
      // if (strMatch : HIGH,2)
      // else if ( strMatch : LOW, 2)
      if(idlOS::strncasecmp("HIGH", (yyvsp[(2) - (4)].strval), 4) != 0 &&
          idlOS::strncasecmp("LOW", (yyvsp[(2) - (4)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 977:

/* Line 1455 of yacc.c  */
#line 6226 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("LOGGING", (yyvsp[(1) - (1)].strval), 7) != 0 &&
           idlOS::strncasecmp("NOLOGGING", (yyvsp[(1) - (1)].strval), 9) != 0 &&
           idlOS::strncasecmp("BUFFER", (yyvsp[(1) - (1)].strval), 6) != 0 &&
           idlOS::strncasecmp("NOBUFFER", (yyvsp[(1) - (1)].strval), 8) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1038:

/* Line 1455 of yacc.c  */
#line 6406 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("NO", (yyvsp[(1) - (2)].strval), 2) != 0 ||
         idlOS::strncasecmp("ACTION", (yyvsp[(2) - (2)].strval), 6) != 0)
      {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1048:

/* Line 1455 of yacc.c  */
#line 6467 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("NO", (yyvsp[(1) - (2)].strval), 2) != 0 ||
           idlOS::strncasecmp("FORCE", (yyvsp[(2) - (2)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1049:

/* Line 1455 of yacc.c  */
#line 6480 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("FORCE", (yyvsp[(1) - (1)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1066:

/* Line 1455 of yacc.c  */
#line 6540 "ulpCompy.y"
    {
      if ( idlOS::strncasecmp( "PRIVATE", (yyvsp[(1) - (1)].strval), 7 ) != 0 )
      {
          // error 처리
          
          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1069:

/* Line 1455 of yacc.c  */
#line 6562 "ulpCompy.y"
    {
      if ( idlOS::strncasecmp( "STOP", (yyvsp[(4) - (4)].strval), 4 ) != 0 )
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }      
  ;}
    break;

  case 1070:

/* Line 1455 of yacc.c  */
#line 6574 "ulpCompy.y"
    {
      if ( idlOS::strncasecmp( "STOP", (yyvsp[(4) - (5)].strval), 4 ) != 0 )
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
      if ( idlOS::strncasecmp( "FORCE", (yyvsp[(5) - (5)].strval), 5 ) != 0 )
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1310:

/* Line 1455 of yacc.c  */
#line 7279 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("IGNORE", (yyvsp[(1) - (2)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1313:

/* Line 1455 of yacc.c  */
#line 7296 "ulpCompy.y"
    {
      if ( idlOS::strncasecmp("SIBLINGS", (yyvsp[(2) - (4)].strval), 8 ) != 0 )
      {
          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
      else
      {
          /* Nothing to do */
      }
  ;}
    break;

  case 1318:

/* Line 1455 of yacc.c  */
#line 7320 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // in host variable
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(1) - (1)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unknown_Hostvar_Error,
                             (yyvsp[(1) - (1)].strval)+1 );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }

        // H_INTEGER, H_INT type
        gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(1) - (1)].strval)+1, sSymNode , gUlpIndName, NULL,
                                          NULL, HV_IN_TYPE);

        gUlpCodeGen.ulpIncHostVarNum( 1 );
        gUlpCodeGen.ulpGenAddHostVarArr( 1 );
    ;}
    break;

  case 1323:

/* Line 1455 of yacc.c  */
#line 7355 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("NOWAIT", (yyvsp[(1) - (1)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }

    ;}
    break;

  case 1336:

/* Line 1455 of yacc.c  */
#line 7405 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SHARE", (yyvsp[(2) - (2)].strval), 5) != 0 &&
           idlOS::strncasecmp("EXCLUSIVE", (yyvsp[(2) - (2)].strval), 9) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1337:

/* Line 1455 of yacc.c  */
#line 7419 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SHARE", (yyvsp[(1) - (2)].strval), 5) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1338:

/* Line 1455 of yacc.c  */
#line 7432 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SHARE", (yyvsp[(1) - (3)].strval), 5) != 0 ||
           idlOS::strncasecmp("EXCLUSIVE", (yyvsp[(3) - (3)].strval), 9) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1339:

/* Line 1455 of yacc.c  */
#line 7447 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("SHARE", (yyvsp[(1) - (1)].strval), 5) != 0 &&
           idlOS::strncasecmp("EXCLUSIVE", (yyvsp[(1) - (1)].strval), 9) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1341:

/* Line 1455 of yacc.c  */
#line 7465 "ulpCompy.y"
    {
        if ( idlOS::strncasecmp( "DDL",  (yyvsp[(3) - (3)].strval), 3 ) != 0 )
        {
            // error 처리
            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
        }
        else
        {
            /* Nothing to do */
        }
    ;}
    break;

  case 1379:

/* Line 1455 of yacc.c  */
#line 7550 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("ISOPEN", (yyvsp[(3) - (3)].strval), 6) != 0 &&
           idlOS::strncasecmp("NOTFOUND", (yyvsp[(3) - (3)].strval), 8) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1600:

/* Line 1455 of yacc.c  */
#line 8270 "ulpCompy.y"
    {
        if(idlOS::strncasecmp("RECORD", (yyvsp[(4) - (8)].strval), 6) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1719:

/* Line 1455 of yacc.c  */
#line 8713 "ulpCompy.y"
    {
        // strMatch : INITSIZE, 1
        if(idlOS::strncasecmp("INITSIZE", (yyvsp[(1) - (3)].strval), 8) != 0)
        {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    ;}
    break;

  case 1725:

/* Line 1455 of yacc.c  */
#line 8751 "ulpCompy.y"
    {
          if(idlOS::strncasecmp("CHARACTER", (yyvsp[(1) - (3)].strval), 9) != 0)
          {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
          }
      ;}
    break;

  case 1726:

/* Line 1455 of yacc.c  */
#line 8769 "ulpCompy.y"
    {
          if( (idlOS::strncasecmp("NATIONAL", (yyvsp[(1) - (4)].strval), 8) != 0) &&
              (idlOS::strncasecmp("CHARACTER", (yyvsp[(2) - (4)].strval), 9) != 0) )
          {
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
          }
      ;}
    break;

  case 1733:

/* Line 1455 of yacc.c  */
#line 8791 "ulpCompy.y"
    {
      // strMatch : DATAFILE, 4
      if(idlOS::strncasecmp("DATAFILE", (yyvsp[(4) - (6)].strval), 8) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1734:

/* Line 1455 of yacc.c  */
#line 8804 "ulpCompy.y"
    {
      // strMatch : DATAFILE, 4
      if(idlOS::strncasecmp("DATAFILE", (yyvsp[(4) - (7)].strval), 8) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1736:

/* Line 1455 of yacc.c  */
#line 8819 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("SNAPSHOT", (yyvsp[(4) - (4)].strval), 8) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1737:

/* Line 1455 of yacc.c  */
#line 8832 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("SNAPSHOT", (yyvsp[(4) - (4)].strval), 8) != 0)
      {
          // error 처리
          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1739:

/* Line 1455 of yacc.c  */
#line 8847 "ulpCompy.y"
    {
      // strMatch : CANCEL, 2
      if(idlOS::strncasecmp("CANCEL", (yyvsp[(2) - (2)].strval), 6) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1740:

/* Line 1455 of yacc.c  */
#line 8860 "ulpCompy.y"
    {
      // strMatch : TIME, 2
      if(idlOS::strncasecmp("TIME", (yyvsp[(2) - (3)].strval), 4) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1745:

/* Line 1455 of yacc.c  */
#line 8886 "ulpCompy.y"
    {
    // strMatch : 1) PROCESS
    //            2) CONTROL
    //            3) SERVICE
    //            4) META    , 1
    if(idlOS::strncasecmp("PROCESS", (yyvsp[(1) - (1)].strval), 7) != 0 &&
       idlOS::strncasecmp("CONTROL", (yyvsp[(1) - (1)].strval), 7) != 0 &&
       idlOS::strncasecmp("SERVICE", (yyvsp[(1) - (1)].strval), 7) != 0 &&
       idlOS::strncasecmp("META", (yyvsp[(1) - (1)].strval), 4) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1746:

/* Line 1455 of yacc.c  */
#line 8905 "ulpCompy.y"
    {
    // strMatch : 1) META  UPGRADE
    //            2) META RESETLOGS
    //            3) META RESETUNDO
    //            4) SHUTDOWN NORMAL
    if(idlOS::strncasecmp("META", (yyvsp[(1) - (2)].strval), 4) == 0 &&
       idlOS::strncasecmp("UPGRADE", (yyvsp[(2) - (2)].strval), 7) == 0)
    {
    }
    else if(idlOS::strncasecmp("META", (yyvsp[(1) - (2)].strval), 4) == 0 &&
            idlOS::strncasecmp("RESETLOGS", (yyvsp[(2) - (2)].strval), 9) == 0)
    {
    }
    else if(idlOS::strncasecmp("META", (yyvsp[(1) - (2)].strval), 4) == 0 &&
            idlOS::strncasecmp("RESETUNDO", (yyvsp[(2) - (2)].strval), 9) == 0)
    {
    }
    else if(idlOS::strncasecmp("SHUTDOWN", (yyvsp[(1) - (2)].strval), 8) == 0 &&
            idlOS::strncasecmp("NORMAL", (yyvsp[(2) - (2)].strval), 6) == 0)
    {
    }
    else
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1747:

/* Line 1455 of yacc.c  */
#line 8937 "ulpCompy.y"
    {
    // strMatch : SHUTDOWN, 1
    if(idlOS::strncasecmp("SHUTDOWN", (yyvsp[(1) - (2)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1748:

/* Line 1455 of yacc.c  */
#line 8950 "ulpCompy.y"
    {
    // strMatch : SHUTDOWN, 1
    if(idlOS::strncasecmp("SHUTDOWN", (yyvsp[(1) - (2)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1750:

/* Line 1455 of yacc.c  */
#line 8967 "ulpCompy.y"
    {
    // strMatch : DTX, 1
    if(idlOS::strncasecmp("DTX", (yyvsp[(1) - (3)].strval), 3) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1751:

/* Line 1455 of yacc.c  */
#line 8980 "ulpCompy.y"
    {
    // strMatch : DTX, 1
    if(idlOS::strncasecmp("DTX", (yyvsp[(1) - (3)].strval), 3) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1753:

/* Line 1455 of yacc.c  */
#line 9002 "ulpCompy.y"
    {
    // strMatch : DATAFILE, 4
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(4) - (6)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1754:

/* Line 1455 of yacc.c  */
#line 9021 "ulpCompy.y"
    {
      // strMatch : SIZE 5,
      if (idlOS::strncasecmp("SIZE", (yyvsp[(5) - (7)].strval), 4) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1755:

/* Line 1455 of yacc.c  */
#line 9041 "ulpCompy.y"
    {
      // strMatch : SIZE 5,
      if (idlOS::strncasecmp("SIZE", (yyvsp[(5) - (8)].strval), 4) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
      if(idlOS::strncasecmp("K", (yyvsp[(7) - (8)].strval), 1) != 0 &&
         idlOS::strncasecmp("M", (yyvsp[(7) - (8)].strval), 1) != 0 &&
         idlOS::strncasecmp("G", (yyvsp[(7) - (8)].strval), 1) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1756:

/* Line 1455 of yacc.c  */
#line 9070 "ulpCompy.y"
    {
    // strMatch : TEMPFILE, 5
    if(idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (7)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1758:

/* Line 1455 of yacc.c  */
#line 9090 "ulpCompy.y"
    {
    // strMatch : 1) DATAFILE, 5
    //            2) TEMPFILE, 5
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(5) - (8)].strval), 8) != 0 &&
       idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (8)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1759:

/* Line 1455 of yacc.c  */
#line 9106 "ulpCompy.y"
    {
    // strMatch : 1) DATAFILE, 5
    //            2) TEMPFILE, 5
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(5) - (7)].strval), 8) != 0 &&
       idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (7)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1763:

/* Line 1455 of yacc.c  */
#line 9131 "ulpCompy.y"
    {
    // strMatch : 1) DATAFILE, 5
    //            2) TEMPFILE, 5
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(5) - (6)].strval), 8) != 0 &&
       idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (6)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1764:

/* Line 1455 of yacc.c  */
#line 9147 "ulpCompy.y"
    {
    // strMatch : 1) DATAFILE, 5
    //            2) TEMPFILE, 5
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(5) - (6)].strval), 8) != 0 &&
       idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (6)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1765:

/* Line 1455 of yacc.c  */
#line 9163 "ulpCompy.y"
    {
    // strMatch : 1) DATAFILE, 5
    //            2) TEMPFILE, 5
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(5) - (7)].strval), 8) != 0 &&
       idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (7)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1766:

/* Line 1455 of yacc.c  */
#line 9180 "ulpCompy.y"
    {
    // strMatch : 1) DATAFILE, 5 && SIZE, 7
    //            2) TEMPFILE, 5 && SIZE, 7
    if(idlOS::strncasecmp("DATAFILE", (yyvsp[(5) - (8)].strval), 8) == 0 &&
       idlOS::strncasecmp("SIZE", (yyvsp[(7) - (8)].strval), 4) == 0)
    {
    }
    else if (idlOS::strncasecmp("TEMPFILE", (yyvsp[(5) - (8)].strval), 8) == 0 &&
             idlOS::strncasecmp("SIZE", (yyvsp[(7) - (8)].strval), 4) == 0)
    {
    }
    else
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1771:

/* Line 1455 of yacc.c  */
#line 9218 "ulpCompy.y"
    {
    // strMatch : SIZE, 2
    if(idlOS::strncasecmp("SIZE", (yyvsp[(2) - (4)].strval), 4) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1772:

/* Line 1455 of yacc.c  */
#line 9233 "ulpCompy.y"
    {
    // if ( strMatch : SIZE, 2)
    // {
    //    if ( strMatch : REUSE, 4)
    //    else if ( strMatch : K, 4)
    //    else if ( strMatch : M, 4)
    //    else if ( strMatch : G, 4)
    // }
    if(idlOS::strncasecmp("SIZE", (yyvsp[(2) - (5)].strval), 4) != 0 ||
       idlOS::strncasecmp("REUSE", (yyvsp[(4) - (5)].strval), 5) != 0 &&
       idlOS::strncasecmp("K", (yyvsp[(4) - (5)].strval), 1) != 0 &&
       idlOS::strncasecmp("M", (yyvsp[(4) - (5)].strval), 1) != 0 &&
       idlOS::strncasecmp("G", (yyvsp[(4) - (5)].strval), 1) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1773:

/* Line 1455 of yacc.c  */
#line 9257 "ulpCompy.y"
    {
    // strMatch : REUSE, 2
    if(idlOS::strncasecmp("REUSE", (yyvsp[(2) - (3)].strval), 5) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1774:

/* Line 1455 of yacc.c  */
#line 9271 "ulpCompy.y"
    {
    // if ( strMatch : SIZE, 2 && REUSE, 5)
    // {
    //    if ( strMatch : K, 4)
    //    else if ( strMatch : M, 4)
    //    else if ( strMatch : G, 4)
    // }
    if(idlOS::strncasecmp("SIZE", (yyvsp[(2) - (6)].strval), 4) != 0 ||
       idlOS::strncasecmp("REUSE", (yyvsp[(5) - (6)].strval), 5) != 0 ||
       idlOS::strncasecmp("K", (yyvsp[(4) - (6)].strval), 1) != 0 &&
       idlOS::strncasecmp("M", (yyvsp[(4) - (6)].strval), 1) != 0 &&
       idlOS::strncasecmp("G", (yyvsp[(4) - (6)].strval), 1) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1777:

/* Line 1455 of yacc.c  */
#line 9302 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (2)].strval), 10) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1778:

/* Line 1455 of yacc.c  */
#line 9316 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (2)].strval), 10) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1779:

/* Line 1455 of yacc.c  */
#line 9331 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (4)].strval), 10) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1780:

/* Line 1455 of yacc.c  */
#line 9346 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    // strMatch : MAXSIZE, 3
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (4)].strval), 10) != 0 ||
       idlOS::strncasecmp("MAXSIZE", (yyvsp[(3) - (4)].strval), 7) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1781:

/* Line 1455 of yacc.c  */
#line 9362 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (5)].strval), 10) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1782:

/* Line 1455 of yacc.c  */
#line 9376 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    // strMatch : K|M|G, 5
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (6)].strval), 10) != 0 ||
       idlOS::strncasecmp("K", (yyvsp[(5) - (6)].strval), 1) != 0 &&
       idlOS::strncasecmp("M", (yyvsp[(5) - (6)].strval), 1) != 0 &&
       idlOS::strncasecmp("G", (yyvsp[(5) - (6)].strval), 1) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1783:

/* Line 1455 of yacc.c  */
#line 9394 "ulpCompy.y"
    {
    // strMatch : AUTOEXTEND, 1
    // strMatch : MAXSIZE, 3
    // strMatch : UNLIMITED, 4
    if(idlOS::strncasecmp("AUTOEXTEND", (yyvsp[(1) - (4)].strval), 10) != 0 ||
       idlOS::strncasecmp("MAXSIZE", (yyvsp[(3) - (4)].strval), 7) != 0 ||
       idlOS::strncasecmp("UNLIMITED", (yyvsp[(4) - (4)].strval), 9) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1784:

/* Line 1455 of yacc.c  */
#line 9415 "ulpCompy.y"
    {
    // if( strMatch : MAXSIZE, 1 && UNLIMITED, 2)
    if(idlOS::strncasecmp("MAXSIZE", (yyvsp[(1) - (2)].strval), 7) != 0 ||
       idlOS::strncasecmp("UNLIMITED", (yyvsp[(2) - (2)].strval), 9) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1785:

/* Line 1455 of yacc.c  */
#line 9431 "ulpCompy.y"
    {
    // if( strMatch : MAXSIZE, 1)
    if(idlOS::strncasecmp("MAXSIZE", (yyvsp[(1) - (2)].strval), 7) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1796:

/* Line 1455 of yacc.c  */
#line 9472 "ulpCompy.y"
    {
    // if ( strMatch : K, 2 )
    // else if ( strMatch : M, 2)
    // else if ( strMatch : G, 2)
    if(idlOS::strncasecmp("K", (yyvsp[(2) - (2)].strval), 1) != 0 &&
       idlOS::strncasecmp("M", (yyvsp[(2) - (2)].strval), 1) != 0 &&
       idlOS::strncasecmp("G", (yyvsp[(2) - (2)].strval), 1) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1798:

/* Line 1455 of yacc.c  */
#line 9493 "ulpCompy.y"
    {
    // if ( strMatch : K, 2 )
    // else if ( strMatch : M, 2)
    // else if ( strMatch : G, 2)
    if(idlOS::strncasecmp("K", (yyvsp[(2) - (2)].strval), 1) != 0 &&
       idlOS::strncasecmp("M", (yyvsp[(2) - (2)].strval), 1) != 0 &&
       idlOS::strncasecmp("G", (yyvsp[(2) - (2)].strval), 1) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1807:

/* Line 1455 of yacc.c  */
#line 9534 "ulpCompy.y"
    {
    // if ( strMatch: INCLUDING, 1 && CONTENTS, 2 )
    if(idlOS::strncasecmp("INCLUDING", (yyvsp[(1) - (3)].strval), 9) != 0 ||
       idlOS::strncasecmp("CONTENTS", (yyvsp[(2) - (3)].strval), 8) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1808:

/* Line 1455 of yacc.c  */
#line 9549 "ulpCompy.y"
    {
    // if ( strMatch: INCLUDING, 1 && CONTENTS, 2 && DATAFILES, 4 )
    if(idlOS::strncasecmp("INCLUDING", (yyvsp[(1) - (5)].strval), 9) != 0 ||
       idlOS::strncasecmp("CONTENTS", (yyvsp[(2) - (5)].strval), 8) != 0 ||
       idlOS::strncasecmp("DATAFILES", (yyvsp[(4) - (5)].strval), 9) != 0)
    {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
  ;}
    break;

  case 1853:

/* Line 1455 of yacc.c  */
#line 9702 "ulpCompy.y"
    {
    /* BUILD [IMMEDIATE | DEFERRED] */
    /* REFRESH [COMPLETE | FAST | FORCE] */
    /* NEVER REFRESH */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "BUILD", (yyvsp[(1) - (2)].strval), 5 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "IMMEDIATE", (yyvsp[(2) - (2)].strval), 9 ) == 0 ) ||
             ( idlOS::strncasecmp( "DEFERRED", (yyvsp[(2) - (2)].strval), 8 ) == 0 ) )
        {
            sPassFlag = ID_TRUE;
        }
        else
        {
            /* Nothing to do */
        }
    }
    else if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(1) - (2)].strval), 7 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "FORCE", (yyvsp[(2) - (2)].strval), 5 ) == 0 ) ||
             ( idlOS::strncasecmp( "COMPLETE", (yyvsp[(2) - (2)].strval), 8 ) == 0 ) ||
             ( idlOS::strncasecmp( "FAST", (yyvsp[(2) - (2)].strval), 4 ) == 0 ) )
        {
            sPassFlag = ID_TRUE;
        }
        else
        {
            /* Nothing to do */
        }
    }
    else if ( idlOS::strncasecmp( "NEVER", (yyvsp[(1) - (2)].strval), 5 ) == 0 )
    {
        if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(2) - (2)].strval), 7 ) == 0 )
        {
            sPassFlag = ID_TRUE;
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1854:

/* Line 1455 of yacc.c  */
#line 9762 "ulpCompy.y"
    {
    /* REFRESH [ON DEMAND | ON COMMIT] */
    if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(1) - (2)].strval), 7 ) == 0 )
    {
        /* Nothing to do */
    }
    else
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
  ;}
    break;

  case 1855:

/* Line 1455 of yacc.c  */
#line 9777 "ulpCompy.y"
    {
    /* REFRESH [COMPLETE | FAST | FORCE] [ON DEMAND | ON COMMIT] */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(1) - (3)].strval), 7 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "FORCE", (yyvsp[(2) - (3)].strval), 5 ) == 0 ) ||
             ( idlOS::strncasecmp( "COMPLETE", (yyvsp[(2) - (3)].strval), 8 ) == 0 ) ||
             ( idlOS::strncasecmp( "FAST", (yyvsp[(2) - (3)].strval), 4 ) == 0 ) )
        {
            sPassFlag = ID_TRUE;
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1856:

/* Line 1455 of yacc.c  */
#line 9812 "ulpCompy.y"
    {
    /* BUILD [IMMEDIATE | DEFERRED] REFRESH [COMPLETE | FAST | FORCE] */
    /* BUILD [IMMEDIATE | DEFERRED] NEVER REFRESH */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "BUILD", (yyvsp[(1) - (4)].strval), 5 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "IMMEDIATE", (yyvsp[(2) - (4)].strval), 9 ) == 0 ) ||
             ( idlOS::strncasecmp( "DEFERRED", (yyvsp[(2) - (4)].strval), 8 ) == 0 ) )
        {
            if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(3) - (4)].strval), 7 ) == 0 )
            {
                if ( ( idlOS::strncasecmp( "FORCE", (yyvsp[(4) - (4)].strval), 5 ) == 0 ) ||
                     ( idlOS::strncasecmp( "COMPLETE", (yyvsp[(4) - (4)].strval), 8 ) == 0 ) ||
                     ( idlOS::strncasecmp( "FAST", (yyvsp[(4) - (4)].strval), 4 ) == 0 ) )
                {
                    sPassFlag = ID_TRUE;
                }
                else
                {
                    /* Nothing to do */
                }
            }
            else if ( idlOS::strncasecmp( "NEVER", (yyvsp[(3) - (4)].strval), 5 ) == 0 )
            {
                if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(4) - (4)].strval), 7 ) == 0 )
                {
                    sPassFlag = ID_TRUE;
                }
                else
                {
                    /* Nothing to do */
                }
            }
            else
            {
                /* Nothing to do */
            }
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1857:

/* Line 1455 of yacc.c  */
#line 9874 "ulpCompy.y"
    {
    /* BUILD [IMMEDIATE | DEFERRED] REFRESH [ON DEMAND | ON COMMIT] */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "BUILD", (yyvsp[(1) - (4)].strval), 5 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "IMMEDIATE", (yyvsp[(2) - (4)].strval), 9 ) == 0 ) ||
             ( idlOS::strncasecmp( "DEFERRED", (yyvsp[(2) - (4)].strval), 8 ) == 0 ) )
        {
            if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(3) - (4)].strval), 7 ) == 0 )
            {
                sPassFlag = ID_TRUE;
            }
            else
            {
                /* Nothing to do */
            }
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1858:

/* Line 1455 of yacc.c  */
#line 9915 "ulpCompy.y"
    {
    /* BUILD [IMMEDIATE | DEFERRED] REFRESH [COMPLETE | FAST | FORCE] [ON DEMAND | ON COMMIT] */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "BUILD", (yyvsp[(1) - (5)].strval), 5 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "IMMEDIATE", (yyvsp[(2) - (5)].strval), 9 ) == 0 ) ||
             ( idlOS::strncasecmp( "DEFERRED", (yyvsp[(2) - (5)].strval), 8 ) == 0 ) )
        {
            if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(3) - (5)].strval), 7 ) == 0 )
            {
                if ( ( idlOS::strncasecmp( "FORCE", (yyvsp[(4) - (5)].strval), 5 ) == 0 ) ||
                     ( idlOS::strncasecmp( "COMPLETE", (yyvsp[(4) - (5)].strval), 8 ) == 0 ) ||
                     ( idlOS::strncasecmp( "FAST", (yyvsp[(4) - (5)].strval), 4 ) == 0 ) )
                {
                    sPassFlag = ID_TRUE;
                }
                else
                {
                    /* Nothing to do */
                }
            }
            else
            {
                /* Nothing to do */
            }
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1859:

/* Line 1455 of yacc.c  */
#line 9968 "ulpCompy.y"
    {
    if ( idlOS::strncasecmp( "DEMAND", (yyvsp[(2) - (2)].strval), 6 ) == 0 )
    {
        /* Nothing to do */
    }
    else
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
  ;}
    break;

  case 1862:

/* Line 1455 of yacc.c  */
#line 9991 "ulpCompy.y"
    {
    /* REFRESH [COMPLETE | FAST | FORCE] */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(1) - (2)].strval), 7 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "FORCE", (yyvsp[(2) - (2)].strval), 5 ) == 0 ) ||
             ( idlOS::strncasecmp( "COMPLETE", (yyvsp[(2) - (2)].strval), 8 ) == 0 ) ||
             ( idlOS::strncasecmp( "FAST", (yyvsp[(2) - (2)].strval), 4 ) == 0 ) )
        {
            sPassFlag = ID_TRUE;
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1863:

/* Line 1455 of yacc.c  */
#line 10026 "ulpCompy.y"
    {
    /* REFRESH [ON DEMAND | ON COMMIT] */
    if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(1) - (2)].strval), 7 ) == 0 )
    {
        /* Nothing to do */
    }
    else
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
  ;}
    break;

  case 1864:

/* Line 1455 of yacc.c  */
#line 10041 "ulpCompy.y"
    {
    /* REFRESH [COMPLETE | FAST | FORCE] [ON DEMAND | ON COMMIT] */
    idBool sPassFlag = ID_FALSE;

    if ( idlOS::strncasecmp( "REFRESH", (yyvsp[(1) - (3)].strval), 7 ) == 0 )
    {
        if ( ( idlOS::strncasecmp( "FORCE", (yyvsp[(2) - (3)].strval), 5 ) == 0 ) ||
             ( idlOS::strncasecmp( "COMPLETE", (yyvsp[(2) - (3)].strval), 8 ) == 0 ) ||
             ( idlOS::strncasecmp( "FAST", (yyvsp[(2) - (3)].strval), 4 ) == 0 ) )
        {
            sPassFlag = ID_TRUE;
        }
        else
        {
            /* Nothing to do */
        }
    }
    else
    {
        /* Nothing to do */
    }

    if ( sPassFlag != ID_TRUE )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unterminated_String_Error );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
    }
    else
    {
        /* Nothing to do */
    }
  ;}
    break;

  case 1866:

/* Line 1455 of yacc.c  */
#line 10092 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (11)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1879:

/* Line 1455 of yacc.c  */
#line 10144 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (6)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }

  ;}
    break;

  case 1880:

/* Line 1455 of yacc.c  */
#line 10157 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (6)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }

  ;}
    break;

  case 1881:

/* Line 1455 of yacc.c  */
#line 10170 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (6)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }

  ;}
    break;

  case 1882:

/* Line 1455 of yacc.c  */
#line 10183 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (5)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1883:

/* Line 1455 of yacc.c  */
#line 10195 "ulpCompy.y"
    {
      // BUG-41713 each job enable disable
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (5)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1884:

/* Line 1455 of yacc.c  */
#line 10208 "ulpCompy.y"
    {
      // BUG-41713 each job enable disable
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (5)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1885:

/* Line 1455 of yacc.c  */
#line 10224 "ulpCompy.y"
    {
      if(idlOS::strncasecmp("JOB", (yyvsp[(2) - (3)].strval), 3) != 0)
      {
          // error 처리

          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
      }
  ;}
    break;

  case 1888:

/* Line 1455 of yacc.c  */
#line 10248 "ulpCompy.y"
    {
        // yyvsp is a internal variable for bison,
        // host value in/out type = HV_IN_TYPE,
        // host value file type = HV_FILE_NONE,
        // Does it need to transform the query? = TRUE
        // num of tokens = 2,
        // index of host value token = 1,
        // indexs of remove token = 0 (it means none)
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)2,
                              (SInt)1,
                              (SInt)0
                            );
    ;}
    break;

  case 1889:

/* Line 1455 of yacc.c  */
#line 10266 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_BLOB,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)1
                            );
    ;}
    break;

  case 1890:

/* Line 1455 of yacc.c  */
#line 10277 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_CLOB,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)1
                            );
    ;}
    break;

  case 1891:

/* Line 1455 of yacc.c  */
#line 10288 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)4,
                              (SInt)3,
                              (SInt)0
                            );
    ;}
    break;

  case 1892:

/* Line 1455 of yacc.c  */
#line 10299 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_BLOB,
                              ID_FALSE,
                              (SInt)6,
                              (SInt)4,
                              (SInt)3
                            );
    ;}
    break;

  case 1893:

/* Line 1455 of yacc.c  */
#line 10310 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_CLOB,
                              ID_FALSE,
                              (SInt)6,
                              (SInt)4,
                              (SInt)3
                            );
    ;}
    break;

  case 1894:

/* Line 1455 of yacc.c  */
#line 10324 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)3,
                              (SInt)1,
                              (SInt)2
                            );
    ;}
    break;

  case 1895:

/* Line 1455 of yacc.c  */
#line 10335 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_PSM_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)3,
                              (SInt)1,
                              (SInt)2
                            );
    ;}
    break;

  case 1896:

/* Line 1455 of yacc.c  */
#line 10346 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_INOUT_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)4,
                              (SInt)1,
                              (SInt)32
                            );
    ;}
    break;

  case 1897:

/* Line 1455 of yacc.c  */
#line 10357 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)2,
                              (SInt)1,
                              (SInt)0
                            );
    ;}
    break;

  case 1898:

/* Line 1455 of yacc.c  */
#line 10368 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_BLOB,
                              ID_TRUE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)1
                            );
    ;}
    break;

  case 1899:

/* Line 1455 of yacc.c  */
#line 10379 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_IN_TYPE,
                              HV_FILE_CLOB,
                              ID_TRUE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)1
                            );
    ;}
    break;

  case 1900:

/* Line 1455 of yacc.c  */
#line 10393 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // in host variable
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(3) - (3)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unknown_Hostvar_Error,
                             (yyvsp[(3) - (3)].strval)+1 );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            if( (sSymNode -> mType != H_BLOBLOCATOR) &&
                (sSymNode -> mType != H_CLOBLOCATOR) )
            {
                //host 변수 type error
                // error 처리

                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_COMP_Lob_Locator_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }

            gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(3) - (3)].strval)+1, sSymNode ,
                                              gUlpIndName, NULL, NULL, HV_IN_TYPE);

            gUlpCodeGen.ulpIncHostVarNum( 1 );
            gUlpCodeGen.ulpGenAddHostVarArr( 1 );
        }

    ;}
    break;

  case 1901:

/* Line 1455 of yacc.c  */
#line 10431 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        // in host variable
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(1) - (1)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unknown_Hostvar_Error,
                             (yyvsp[(1) - (1)].strval)+1 );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            gUlpCodeGen.ulpGenAddHostVarList( (yyvsp[(1) - (1)].strval)+1, sSymNode ,
                                              gUlpIndName, NULL, NULL, HV_IN_TYPE);

            gUlpCodeGen.ulpIncHostVarNum( 1 );
            gUlpCodeGen.ulpGenAddHostVarArr( 1 );
        }
    ;}
    break;

  case 1903:

/* Line 1455 of yacc.c  */
#line 10460 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(1) - (2)].strval) );
    ;}
    break;

  case 1904:

/* Line 1455 of yacc.c  */
#line 10467 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_NONE,
                              ID_FALSE,
                              (SInt)2,
                              (SInt)1,
                              (SInt)1
                            );
    ;}
    break;

  case 1905:

/* Line 1455 of yacc.c  */
#line 10478 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_NONE,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)3,
                              (SInt)23
                            );
    ;}
    break;

  case 1906:

/* Line 1455 of yacc.c  */
#line 10489 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_BLOB,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)12
                            );
    ;}
    break;

  case 1907:

/* Line 1455 of yacc.c  */
#line 10500 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_CLOB,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)12
                            );
    ;}
    break;

  case 1908:

/* Line 1455 of yacc.c  */
#line 10511 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_BLOB,
                              ID_FALSE,
                              (SInt)6,
                              (SInt)4,
                              (SInt)234
                            );
    ;}
    break;

  case 1909:

/* Line 1455 of yacc.c  */
#line 10522 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_CLOB,
                              ID_FALSE,
                              (SInt)6,
                              (SInt)4,
                              (SInt)234
                            );
    ;}
    break;

  case 1911:

/* Line 1455 of yacc.c  */
#line 10537 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(1) - (2)].strval) );
    ;}
    break;

  case 1914:

/* Line 1455 of yacc.c  */
#line 10549 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_NONE,
                              ID_FALSE,
                              (SInt)2,
                              (SInt)1,
                              (SInt)1
                            );
    ;}
    break;

  case 1915:

/* Line 1455 of yacc.c  */
#line 10560 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_NONE,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)3,
                              (SInt)23
                            );
    ;}
    break;

  case 1916:

/* Line 1455 of yacc.c  */
#line 10571 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_BLOB,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)12
                            );
    ;}
    break;

  case 1917:

/* Line 1455 of yacc.c  */
#line 10582 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_CLOB,
                              ID_FALSE,
                              (SInt)4,
                              (SInt)2,
                              (SInt)12
                            );
    ;}
    break;

  case 1918:

/* Line 1455 of yacc.c  */
#line 10593 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_BLOB,
                              ID_FALSE,
                              (SInt)6,
                              (SInt)4,
                              (SInt)234
                            );
    ;}
    break;

  case 1919:

/* Line 1455 of yacc.c  */
#line 10604 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_TYPE,
                              HV_FILE_CLOB,
                              ID_FALSE,
                              (SInt)6,
                              (SInt)4,
                              (SInt)234
                            );
    ;}
    break;

  case 1920:

/* Line 1455 of yacc.c  */
#line 10618 "ulpCompy.y"
    {
        ulpValidateHostValue( yyvsp,
                              HV_OUT_PSM_TYPE,
                              HV_FILE_NONE,
                              ID_TRUE,
                              (SInt)2,
                              (SInt)1,
                              (SInt)0
                            );
    ;}
    break;

  case 1921:

/* Line 1455 of yacc.c  */
#line 10633 "ulpCompy.y"
    {
        ulpSymTElement *sSymNode;

        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(2) - (2)].strval) );

        // out host variable
        if ( ( sSymNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (2)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unknown_Hostvar_Error,
                             (yyvsp[(2) - (2)].strval)+1 );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            idlOS::snprintf( gUlpFileOptName, MAX_HOSTVAR_NAME_SIZE * 2,
                             "%s", (yyvsp[(2) - (2)].strval)+1);
        }
    ;}
    break;

  case 1923:

/* Line 1455 of yacc.c  */
#line 10661 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(1) - (1)].strval) );
    ;}
    break;

  case 1926:

/* Line 1455 of yacc.c  */
#line 10673 "ulpCompy.y"
    {
        ulpSymTNode *sFieldSymNode;

        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(2) - (2)].strval) );
        if ( ( gUlpIndNode = gUlpScopeT.ulpSLookupAll( (yyvsp[(2) - (2)].strval)+1, gUlpCurDepth ) ) == NULL )
        {
            //host 변수 못찾는 error
            // error 처리

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Unknown_Hostvar_Error,
                             (yyvsp[(2) - (2)].strval)+1 );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
        else
        {
            /* BUG-28566: The indicator must be the type of SQLLEN or int or long(32bit). */
            if( (gUlpIndNode->mIsstruct   == ID_TRUE) &&
                (gUlpIndNode->mStructLink != NULL) )
            {   // indicator가 struct type이라면 모든 필드들은 int/long or SQLLEN type이어야한다.
                // indicator symbol node(gUlpIndNode)안의 struct node pointer(mStructLink)
                // 를 따라가 field hash table(mChild)의 symbol node(mInOrderList)를
                // 얻어온다.
                sFieldSymNode = gUlpIndNode->mStructLink->mChild->mInOrderList;

                // struct 안의 각 필드들의 type을 검사한다.
                while ( sFieldSymNode != NULL )
                {
                    switch ( sFieldSymNode->mElement.mType )
                    {
                        case H_INT:
                        case H_BLOBLOCATOR:
                        case H_CLOBLOCATOR:
                            break;
                        case H_LONG:
                            // indicator는 무조건 4byte이어야함.
                            if( ID_SIZEOF(long) != 4 )
                            {
                                // 잘못된 indicator type error 처리
                                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                                 ulpERR_ABORT_COMP_Wrong_IndicatorType_Error,
                                                 sFieldSymNode->mElement.mName );
                                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                            }
                            break;
                        default:
                            // 잘못된 indicator type error 처리
                            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                             ulpERR_ABORT_COMP_Wrong_IndicatorType_Error,
                                             sFieldSymNode->mElement.mName );
                            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                            break;
                    }
                    // 다음 field symbol node를 가리킨다.
                    sFieldSymNode = sFieldSymNode->mInOrderNext;
                }
            }
            else
            {   // struct type이 아니다.
                switch( gUlpIndNode->mType )
                {   // must be the type of SQLLEN or int or long(32bit).
                    case H_INT:
                    case H_BLOBLOCATOR:
                    case H_CLOBLOCATOR:
                        break;
                    case H_LONG:
                        // indicator는 무조건 4byte이어야함.
                        if( ID_SIZEOF(long) != 4 )
                        {
                            // 잘못된 indicator type error 처리
                            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                             ulpERR_ABORT_COMP_Wrong_IndicatorType_Error,
                                             sFieldSymNode->mElement.mName );
                            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                        }
                        break;
                    default:
                        // 잘못된 indicator type error 처리
                        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                         ulpERR_ABORT_COMP_Wrong_IndicatorType_Error,
                                         gUlpIndNode->mName );
                        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                        COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                        break;
                }
            }

            idlOS::snprintf( gUlpIndName, MAX_HOSTVAR_NAME_SIZE * 2,
                             "%s", (yyvsp[(2) - (2)].strval)+1);
        }
    ;}
    break;

  case 1928:

/* Line 1455 of yacc.c  */
#line 10773 "ulpCompy.y"
    {
        gUlpCodeGen.ulpGenRemoveQueryToken( (yyvsp[(1) - (1)].strval) );
    ;}
    break;

  case 1936:

/* Line 1455 of yacc.c  */
#line 10795 "ulpCompy.y"
    {
      if ( idlOS::strncasecmp( "APPEND", (yyvsp[(2) - (2)].strval), 6 ) != 0 )
      {
          ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                           ulpERR_ABORT_COMP_Unterminated_String_Error );
          gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
          COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
      }
      else
      {
          /* Nothing to do */
      }
  ;}
    break;



/* Line 1455 of yacc.c  */
#line 15542 "ulpCompy.cpp"
      default: break;
    }
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (YY_("syntax error"));
#else
      {
	YYSIZE_T yysize = yysyntax_error (0, yystate, yychar);
	if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM)
	  {
	    YYSIZE_T yyalloc = 2 * yysize;
	    if (! (yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM))
	      yyalloc = YYSTACK_ALLOC_MAXIMUM;
	    if (yymsg != yymsgbuf)
	      YYSTACK_FREE (yymsg);
	    yymsg = (char *) YYSTACK_ALLOC (yyalloc);
	    if (yymsg)
	      yymsg_alloc = yyalloc;
	    else
	      {
		yymsg = yymsgbuf;
		yymsg_alloc = sizeof yymsgbuf;
	      }
	  }

	if (0 < yysize && yysize <= yymsg_alloc)
	  {
	    (void) yysyntax_error (yymsg, yystate, yychar);
	    yyerror (yymsg);
	  }
	else
	  {
	    yyerror (YY_("syntax error"));
	    if (yysize != 0)
	      goto yyexhaustedlab;
	  }
      }
#endif
    }



  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      if (yychar <= YYEOF)
	{
	  /* Return failure if at end of input.  */
	  if (yychar == YYEOF)
	    YYABORT;
	}
      else
	{
	  yydestruct ("Error: discarding",
		      yytoken, &yylval);
	  yychar = YYEMPTY;
	}
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  /* Do not reclaim the symbols of the rule which action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;	/* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (yyn != YYPACT_NINF)
	{
	  yyn += YYTERROR;
	  if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
	    {
	      yyn = yytable[yyn];
	      if (0 < yyn)
		break;
	    }
	}

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
	YYABORT;


      yydestruct ("Error: popping",
		  yystos[yystate], yyvsp);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  *++yyvsp = yylval;


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined(yyoverflow) || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
     yydestruct ("Cleanup: discarding lookahead",
		 yytoken, &yylval);
  /* Do not reclaim the symbols of the rule which action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
		  yystos[*yyssp], yyvsp);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  /* Make sure YYID is used.  */
  return YYID (yyresult);
}



/* Line 1675 of yacc.c  */
#line 10837 "ulpCompy.y"



int doCOMPparse( SChar *aFilename )
{
/***********************************************************************
 *
 * Description :
 *      COMPparse precompiling을 시작되게 하는 initial 함수.
 *
 ***********************************************************************/
    int sRes;

    ulpCOMPInitialize( aFilename );

    gUlpCOMPifstackMgr[++gUlpCOMPifstackInd] = new ulpPPifstackMgr();

    if( gDontPrint2file != ID_TRUE )
    {
        gUlpCodeGen.ulpGenInitPrint();

        /* BUG-42357 */
        if (gUlpProgOption.mOptLineMacro == ID_TRUE)
        {
            if (gUlpProgOption.mOptParseInfo == PARSE_FULL)
            {
                gUlpCodeGen.ulpGenSetCurFileInfo( COMPlineno, 0, gUlpProgOption.mInFile );
            }
            else
            {
                gUlpCodeGen.ulpGenSetCurFileInfo( COMPlineno, -1, gUlpProgOption.mInFile );
            }

            gUlpCodeGen.ulpGenPrintLineMacro();
        }
    }

    sRes = COMPparse( );

    gUlpCodeGen.ulpGenWriteFile();

    delete gUlpCOMPifstackMgr[gUlpCOMPifstackInd];

    gUlpCOMPifstackInd--;

    ulpCOMPFinalize();

    return sRes;
}


idBool ulpCOMPCheckArray( ulpSymTElement *aSymNode )
{
/***********************************************************************
 *
 * Description :
 *      array binding을 해야할지(isarr을 true로 set할지) 여부를 체크하기 위한 함수.
 *      struct A { int a[10]; } sA; 의 경우 isarr를 true로 set하고, isstruct를 
 *      false로 set하기 위해 사용됨.
 *
 ***********************************************************************/
    ulpSymTNode *sFieldSymNode;

    sFieldSymNode = aSymNode->mStructLink->mChild->mInOrderList;

    IDE_TEST( sFieldSymNode == NULL );

    while ( sFieldSymNode != NULL )
    {
        switch ( sFieldSymNode->mElement.mType )
        {
            case H_CLOB:
            case H_BLOB:
            case H_NUMERIC:
            case H_NIBBLE:
            case H_BIT:
            case H_BYTES:
            case H_BINARY:
            case H_CHAR:
            case H_NCHAR:
            case H_CLOB_FILE:
            case H_BLOB_FILE:
                IDE_TEST( sFieldSymNode->mElement.mArraySize2[0] == '\0' );
                break;
            case H_VARCHAR:
            case H_NVARCHAR:
                IDE_TEST( 1 );
                break;
            default:
                IDE_TEST( sFieldSymNode->mElement.mIsarray != ID_TRUE );
                break;
        }
        sFieldSymNode = sFieldSymNode->mInOrderNext;
    }

    return ID_TRUE;

    IDE_EXCEPTION_END;

    return ID_FALSE;
}


void ulpValidateHostValue( void         *yyvsp,
                           ulpHVarType   aInOutType,
                           ulpHVFileType aFileType,
                           idBool        aTransformQuery,
                           SInt          aNumofTokens,
                           SInt          aHostValIndex,
                           SInt          aRemoveTokIndexs )
{
/***********************************************************************
 *
 * Description :
 *      host 변수가 유효한지 확인하며, 유효하다면 ulpGenHostVarList 에 추가한다.
 *      aNumofTokens는 총 토큰들의 수,
 *      aHostValIndex 는 호스트 변수가 몇번째 토큰에 위치하는지를 나타내며,
 *      aRemoveTokIndexs는 SQL쿼리변환시 몇번째 토큰에 위치하는 토큰들을 제거할지를 나타내준다.
 *      ex> aRemoveTokIndexs이 123이면 1,2,3 에 위치하는 토큰들을 제거해준다.
 *
 ***********************************************************************/
    SInt            sIndexs, sMod;
    SChar          *sFileOptName;
    ulpSymTElement *sSymNode;
    ulpGENhvType    sHVType;
    ulpGENhvType    sArrayStructType;

    switch( aInOutType )
    {
        case HV_IN_TYPE:
            sArrayStructType = IN_GEN_ARRAYSTRUCT;
            break;
        case HV_OUT_TYPE:
        case HV_OUT_PSM_TYPE:
            sArrayStructType = OUT_GEN_ARRAYSTRUCT;
            break;
        case HV_INOUT_TYPE:
            sArrayStructType = INOUT_GEN_ARRAYSTRUCT;
            break;
        default:
            sArrayStructType = GEN_GENERAL;
            break;
    }

    if ( sArrayStructType == INOUT_GEN_ARRAYSTRUCT )
    {
        if ( ((gUlpCodeGen.ulpGenGetEmSQLInfo()->mHostValueType) == IN_GEN_ARRAYSTRUCT) ||
             ((gUlpCodeGen.ulpGenGetEmSQLInfo()->mHostValueType) == OUT_GEN_ARRAYSTRUCT))
        {
            // error 처리
            // array struct type은 다른 host 변수와 같이 올수 없다.

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Repeat_Array_Struct_Error,
                             (*(((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)==':')?
                             (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)+1:
                             (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)
                           );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    }
    else
    {
        if ( (gUlpCodeGen.ulpGenGetEmSQLInfo()->mHostValueType)
             == sArrayStructType )
        {
            // error 처리
            // array struct type은 다른 host 변수와 같이 올수 없다.

            ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                             ulpERR_ABORT_COMP_Repeat_Array_Struct_Error,
                             (*(((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)==':')?
                             (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)+1:
                             (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)
                           );
            gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
            COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
        }
    }

    // lookup host variable
    if ( ( sSymNode = gUlpScopeT.ulpSLookupAll(
                                    (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval),
                                    gUlpCurDepth )
         ) == NULL
       )
    {
        //host 변수 못찾는 error
        // error 처리

        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_COMP_Unknown_Hostvar_Error,
                         (*(((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)==':')?
                         (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)+1:
                         (((YYSTYPE *)yyvsp)[aHostValIndex - aNumofTokens].strval)
                       );
        gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
        COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
    }
    else
    {
        /* BUG-28788 : FOR절을 이용하여 struct pointer type의 array insert가 안됨  */
        if ( (gUlpCodeGen.ulpGenGetEmSQLInfo()->mIters[0] != '\0') && 
             (sSymNode->mPointer <= 0) )
        {
            /* BUG-44577 array or pointer type이 아닌데 FOR절이 왔다면 error를 report함. 
             * array or pointer type이 아니지만 struct type일 경우 struct안의 변수를 체크한다. */
            if ( sSymNode->mIsstruct == ID_TRUE )
            {
                /* BUG-44577 struct안에 배열 변수가 있는지 확인 */
                if ( ulpValidateFORStructArray(sSymNode) != IDE_SUCCESS)
                {
                    ulpSetErrorCode( &gUlpParseInfo.mErrorMgr, ulpERR_ABORT_FORstmt_Invalid_usage_Error );
                    gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                    COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
                }
            }
            else
            {
                ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                 ulpERR_ABORT_FORstmt_Invalid_usage_Error );
                gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                COMPerror( ulpGetErrorMSG(&gUlpParseInfo.mErrorMgr) );
            }
        }
        else
        {
            /* pointer type */
        }

        // 호스트 변수들에 대해 struct,arraystruct type 설정.
        if ( sSymNode->mIsstruct == ID_TRUE )
        {
            if ( sSymNode->mArraySize[0] != '\0' )
            {
                // array struct

                /* BUG-32100 An indicator of arraystructure type should not be used for a hostvariable. */
                if (gUlpIndNode != NULL)
                {
                    // 구조체 배열을 호스트 변수로 사용하면, 인디케이터를 가질 수 없다.
                    ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                                     ulpERR_ABORT_COMP_Invalid_Indicator_Usage_Error );
                    gUlpCOMPErrCode = ulpGetErrorSTATE( &gUlpParseInfo.mErrorMgr );
                    COMPerror( ulpGetErrorMSG( &gUlpParseInfo.mErrorMgr ) );
                }
                else
                {
                    sHVType = sArrayStructType;
                    gUlpCodeGen.ulpGenEmSQL( GEN_HVTYPE, (void *) &sHVType );
                }
            }
            else
            {
                if( ulpCOMPCheckArray ( sSymNode ) == ID_TRUE )
                {
                    // array
                    sHVType = GEN_ARRAY;
                    gUlpCodeGen.ulpGenEmSQL( GEN_HVTYPE, (void *) &sHVType );
                }
                else
                {
                    // struct
                    sHVType = GEN_STRUCT;
                    gUlpCodeGen.ulpGenEmSQL( GEN_HVTYPE, (void *) &sHVType );
                }
            }
        }

        // remove some tokens
        for( sIndexs = aRemoveTokIndexs; sIndexs > 0 ; sIndexs/=10 )
        {
            sMod = sIndexs%10;
            if (sMod > 0)
            {
                gUlpCodeGen.ulpGenRemoveQueryToken(
                        (((YYSTYPE *)yyvsp)[sMod - aNumofTokens].strval)
                                                  );
            }
        }

        // set value type for file mode
        switch(aFileType)
        {
            case HV_FILE_CLOB:
                sSymNode->mType = H_CLOB_FILE;
                sFileOptName = gUlpFileOptName;
                break;
            case HV_FILE_BLOB:
                sSymNode->mType = H_BLOB_FILE;
                sFileOptName = gUlpFileOptName;
                break;
            default:
                sFileOptName = NULL;
                break;
        }

        gUlpCodeGen.ulpGenAddHostVarList(
                        (((YYSTYPE *)yyvsp)[aHostValIndex- aNumofTokens].strval),
                        sSymNode ,
                        gUlpIndName,
                        gUlpIndNode,
                        sFileOptName,
                        aInOutType      );

        if ( sSymNode->mIsstruct == ID_TRUE )
        {
            IDE_ASSERT(sSymNode->mStructLink->mChild != NULL);
            gUlpCodeGen.ulpIncHostVarNum( sSymNode->mStructLink->mChild->mCnt );
            if( aTransformQuery == ID_TRUE )
            {
                gUlpCodeGen.ulpGenAddHostVarArr( sSymNode->mStructLink->mChild->mCnt );
            }
        }
        else
        {
            gUlpCodeGen.ulpIncHostVarNum( 1 );
            if( aTransformQuery == ID_TRUE )
            {
                gUlpCodeGen.ulpGenAddHostVarArr( 1 );
            }
        }
    }

    gUlpIndName[0] = '\0';
    gUlpIndNode    = NULL;

    switch(aFileType)
    {
        case HV_FILE_CLOB:
        case HV_FILE_BLOB:
            gUlpFileOptName[0] = '\0';
            break;
        default:
            break;
    }
}

/* =========================================================
 *  ulpValidateFORStructArray
 *
 *  Description :
 *     ulpValidateHostValue에서 호출되는 함수들로, 
       FOR절에 사용되는 host 변수를 체크한다.
 *
 *  Parameters :  
 *     ulpSymTElement *aElement : 체크해야될 host 변수 정보
 * ========================================================*/
IDE_RC ulpValidateFORStructArray(ulpSymTElement *aElement)
{
    ulpStructTNode *sStructTNode;
    ulpSymTNode    *sSymTNode;
    ulpSymTElement *sFirstFieldNode;
    ulpSymTElement *sFieldNode;
    SInt            i;
        
    sStructTNode    = (ulpStructTNode*)aElement->mStructLink;
    
    /* BUG-44577 struct안에 변수가 없음 */
    IDE_TEST( sStructTNode->mChild->mCnt <= 0 );
    
    sSymTNode       = sStructTNode->mChild->mInOrderList;
    sFirstFieldNode = &(sSymTNode->mElement);
                
    IDE_TEST( (sFirstFieldNode->mIsstruct == ID_TRUE) || (sFirstFieldNode->mIsarray == ID_FALSE));
        
    /* BUG-44577 char type일 경우 무조건 2차원 배열이 와야 한다. */
    if ( (sFirstFieldNode->mType == H_CHAR)    ||
         (sFirstFieldNode->mType == H_VARCHAR) ||
         (sFirstFieldNode->mType == H_NCHAR)   ||
         (sFirstFieldNode->mType == H_NVARCHAR) )
    {
        IDE_TEST( (sFirstFieldNode->mArraySize[0] == '\0') || (sFirstFieldNode->mArraySize2[0] == '\0') );
    }
                
    for (i = 1; i < sStructTNode->mChild->mCnt; i++)
    {
        sSymTNode = sSymTNode->mInOrderNext;
        sFieldNode = &(sSymTNode->mElement);
        
        IDE_TEST( (sFieldNode->mIsstruct == ID_TRUE) || (sFieldNode->mIsarray == ID_FALSE));
        
        /* BUG-44577 char type일 경우 무조건 2차원 배열이 와야 한다. */
        if ( (sFirstFieldNode->mType == H_CHAR)    ||
             (sFirstFieldNode->mType == H_VARCHAR) ||
             (sFirstFieldNode->mType == H_NCHAR)   ||
             (sFirstFieldNode->mType == H_NVARCHAR) )
        {
            IDE_TEST( (sFirstFieldNode->mArraySize[0] == '\0') || (sFirstFieldNode->mArraySize2[0] == '\0') );
        }
        
        IDE_TEST( idlOS::strcmp(sFirstFieldNode->mArraySize, sFieldNode->mArraySize) != 0 );
    }

    return IDE_SUCCESS;
        
    IDE_EXCEPTION_END;
    
    return IDE_FAILURE;
}


/*
 *  Member functions of the ulpParseInfo.
 *
 */

ulpParseInfo::ulpParseInfo()
{
    mSaveId              = ID_FALSE;
    mFuncDecl            = ID_FALSE;
    mStructDeclDepth     = 0;
    mArrDepth            = 0;
    mArrExpr             = ID_FALSE;
    mConstantExprStr[0]  = '\0';
    mStructPtr           = NULL;
    mHostValInfo4Typedef = NULL;
    mVarcharDecl         = ID_FALSE;
    /* BUG-27875 : 구조체안의 typedef type인식못함. */
    mSkipTypedef         = ID_FALSE;

    /* BUG-35518 Shared pointer should be supported in APRE */
    mIsSharedPtr         = ID_FALSE;
    IDU_LIST_INIT( &mSharedPtrVarList );

    IDU_LIST_INIT( &mVarcharVarList );

    /* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
     * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
    mHostValInfo[mStructDeclDepth]
            = (ulpSymTElement *) idlOS::malloc( ID_SIZEOF( ulpSymTElement ) );

    if ( mHostValInfo[mStructDeclDepth] == NULL )
    {
        ulpSetErrorCode( &gUlpParseInfo.mErrorMgr,
                         ulpERR_ABORT_Memory_Alloc_Error );
        ulpPrintfErrorCode( stderr,
                            &gUlpParseInfo.mErrorMgr);
        IDE_ASSERT(0);
    }
    else
    {
        (void) ulpInitHostInfo();
    }
}


/* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
 * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
void ulpParseInfo::ulpFinalize(void)
{
/***********************************************************************
 *
 * Description :
 *    malloc 된 mHostValInfo 배열이 free되지 않았다면 free해준다.
 *
 * Implementation :
 *
 ***********************************************************************/

    for( ; mStructDeclDepth >= 0 ; mStructDeclDepth-- )
    {
        idlOS::free( mHostValInfo[mStructDeclDepth] );
        mHostValInfo[mStructDeclDepth] = NULL;
    }
}


/* BUG-28118 : system 헤더파일들도 파싱돼야함.                       *
 * 6th. problem : Nested structure 정의중 scope를 잘못 계산하는 문제 */
void ulpParseInfo::ulpInitHostInfo( void )
{
/***********************************************************************
 *
 * Description :
 *    host 변수 정보 초기화 함수로 특정 host 변수를 파싱하면서 setting된
 *    변수에대한 정보를 파싱을 마친후 본함수가 호출되어 다시 초기화 해준다.
 * Implementation :
 *
 ***********************************************************************/
    mHostValInfo[mStructDeclDepth]->mName[0]       = '\0';
    mHostValInfo[mStructDeclDepth]->mType          = H_UNKNOWN;
    mHostValInfo[mStructDeclDepth]->mIsTypedef     = ID_FALSE;
    mHostValInfo[mStructDeclDepth]->mIsarray       = ID_FALSE;
    mHostValInfo[mStructDeclDepth]->mArraySize[0]  = '\0';
    mHostValInfo[mStructDeclDepth]->mArraySize2[0] = '\0';
    mHostValInfo[mStructDeclDepth]->mIsstruct      = ID_FALSE;
    mHostValInfo[mStructDeclDepth]->mStructName[0] = '\0';
    mHostValInfo[mStructDeclDepth]->mStructLink    = NULL;
    mHostValInfo[mStructDeclDepth]->mIssign        = ID_TRUE;
    mHostValInfo[mStructDeclDepth]->mPointer       = 0;
    mHostValInfo[mStructDeclDepth]->mAlloc         = ID_FALSE;
    mHostValInfo[mStructDeclDepth]->mMoreInfo      = 0;
    mHostValInfo[mStructDeclDepth]->mIsExtern      = ID_FALSE;
}


void ulpParseInfo::ulpCopyHostInfo4Typedef( ulpSymTElement *aD,
                                            ulpSymTElement *aS )
{
/***********************************************************************
 *
 * Description :
 *    typedef 구문 처리를 위한 ulpSymTElement copy 함수로, typedef 된 특정 type을
 *    선언시 사용할때 호출되어 해당 type에 대한 정보를 복사해줌.
 *   예)  typedef struct A { int a; };
          A sA;           <----   이경우 type A에 대한 정보를 변수 sA 정보에 복사해줌.
 * Implementation :
 *
 ***********************************************************************/
    // mIsTypedef, mName은 복사 대상이 아님.
    aD->mType     = aS->mType;
    aD->mIsarray  = aS->mIsarray;
    aD->mIsstruct = aS->mIsstruct;
    aD->mIssign   = aS->mIssign;
    aD->mPointer  = aS->mPointer;
    aD->mAlloc    = aS->mAlloc;
    aD->mIsExtern = aS->mIsExtern;
    if ( aS->mArraySize[0] != '\0' )
    {
        idlOS::strncpy( aD->mArraySize, aS->mArraySize, MAX_NUMBER_LEN - 1 );
    }
    if ( aS->mArraySize2[0] != '\0' )
    {
        idlOS::strncpy( aD->mArraySize2, aS->mArraySize2, MAX_NUMBER_LEN - 1 );
    }
    if ( aS->mStructName[0] != '\0' )
    {
        idlOS::strncpy( aD->mStructName, aS->mStructName, MAX_HOSTVAR_NAME_SIZE - 1 );
    }
    if ( aS->mStructLink != NULL )
    {
        aD->mStructLink  = aS->mStructLink;
    }
}


// for debug : print host variable info.
void ulpParseInfo::ulpPrintHostInfo(void)
{
    idlOS::printf( "\n=== hostvar info ===\n"
                   "mName       =[%s]\n"
                   "mType       =[%d]\n"
                   "mIsTypedef  =[%d]\n"
                   "mIsarray    =[%d]\n"
                   "mArraySize  =[%s]\n"
                   "mArraySize2 =[%s]\n"
                   "mIsstruct   =[%d]\n"
                   "mStructName =[%s]\n"
                   "mStructLink =[%d]\n"
                   "mIssign     =[%d]\n"
                   "mPointer    =[%d]\n"
                   "mAlloc      =[%d]\n"
                   "mIsExtern   =[%d]\n"
                   "====================\n",
                   mHostValInfo[mStructDeclDepth]->mName,
                   mHostValInfo[mStructDeclDepth]->mType,
                   mHostValInfo[mStructDeclDepth]->mIsTypedef,
                   mHostValInfo[mStructDeclDepth]->mIsarray,
                   mHostValInfo[mStructDeclDepth]->mArraySize,
                   mHostValInfo[mStructDeclDepth]->mArraySize2,
                   mHostValInfo[mStructDeclDepth]->mIsstruct,
                   mHostValInfo[mStructDeclDepth]->mStructName,
                   mHostValInfo[mStructDeclDepth]->mStructLink,
                   mHostValInfo[mStructDeclDepth]->mIssign,
                   mHostValInfo[mStructDeclDepth]->mPointer,
                   mHostValInfo[mStructDeclDepth]->mAlloc,
                   mHostValInfo[mStructDeclDepth]->mIsExtern );
}

