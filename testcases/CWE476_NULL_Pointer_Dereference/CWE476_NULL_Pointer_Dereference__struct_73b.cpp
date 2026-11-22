/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE476_NULL_Pointer_Dereference__struct_73b.cpp
Label Definition File: CWE476_NULL_Pointer_Dereference.label.xml
Template File: sources-sinks-73b.tmpl.cpp
*/
/*
 * @description
 * CWE: 476 NULL Pointer Dereference
 * BadSource:  Set data to NULL
 * GoodSource: Initialize data
 * Sinks:
 *    GoodSink: Check for NULL before attempting to print data
 *    BadSink : Print data
 * Flow Variant: 73 Data flow: data passed in a list from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <list>

#include <wchar.h>

using namespace std;

namespace CWE476_NULL_Pointer_Dereference__struct_73
{

#ifndef OMITBAD

void badSink(list<twoIntsStruct *> dataList)
{
    /* copy data out of dataList */
    twoIntsStruct * data = dataList.back();/* ikos[v3.5.2]: warning: pointer 'std::__cxx11::list<_twoIntsStruct*, std::allocator<_twoIntsStruct*> >::back()(&dataList)' might be null */
    /* POTENTIAL FLAW: Attempt to use data, which may be NULL */
    printIntLine(data->intOne);/* ikos[v3.5.2]: warning: pointer '&data->intOne' might be null */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(list<twoIntsStruct *> dataList)
{
    twoIntsStruct * data = dataList.back();/* ikos[v3.5.2]: warning: pointer 'std::__cxx11::list<_twoIntsStruct*, std::allocator<_twoIntsStruct*> >::back()(&dataList)' might be null */
    /* POTENTIAL FLAW: Attempt to use data, which may be NULL */
    printIntLine(data->intOne);/* ikos[v3.5.2]: warning: pointer '&data->intOne' might be null */
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(list<twoIntsStruct *> dataList)
{
    twoIntsStruct * data = dataList.back();/* ikos[v3.5.2]: warning: pointer 'std::__cxx11::list<_twoIntsStruct*, std::allocator<_twoIntsStruct*> >::back()(&dataList)' might be null */
    /* FIX: Check for NULL before attempting to print data */
    if (data != NULL)
    {
        printIntLine(data->intOne);/* ikos[v3.5.2]: warning: pointer '&data->intOne' might be null */
    }
    else
    {
        printLine("data is NULL");
    }
}

#endif /* OMITGOOD */

} /* close namespace */
