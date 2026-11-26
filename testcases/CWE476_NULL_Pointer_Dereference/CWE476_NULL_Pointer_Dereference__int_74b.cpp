/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE476_NULL_Pointer_Dereference__int_74b.cpp
Label Definition File: CWE476_NULL_Pointer_Dereference.label.xml
Template File: sources-sinks-74b.tmpl.cpp
*/
/*
 * @description
 * CWE: 476 NULL Pointer Dereference
 * BadSource:  Set data to NULL
 * GoodSource: Initialize data
 * Sinks:
 *    GoodSink: Check for NULL before attempting to print data
 *    BadSink : Print data
 * Flow Variant: 74 Data flow: data passed in a map from one function to another in different source files
 *
 * */

#include "std_testcase.h"
#include <map>

#include <wchar.h>

using namespace std;

namespace CWE476_NULL_Pointer_Dereference__int_74
{

#ifndef OMITBAD

void badSink(map<int, int *> dataMap)
{
    /* copy data out of dataMap */
    int * data = dataMap[2];/* ikos: warning: pointer 'std::map<int, int*, std::less<int>, std::allocator<std::pair<int const, int*> > >::operator[](int&&)(&dataMap, &__unnamed_local_var)' might be null */
    /* POTENTIAL FLAW: Attempt to use data, which may be NULL */
    printIntLine(*data);/* ikos: warning: pointer 'data' might be null */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void goodG2BSink(map<int, int *> dataMap)
{
    int * data = dataMap[2];/* ikos: warning: pointer 'std::map<int, int*, std::less<int>, std::allocator<std::pair<int const, int*> > >::operator[](int&&)(&dataMap, &__unnamed_local_var)' might be null */
    /* POTENTIAL FLAW: Attempt to use data, which may be NULL */
    printIntLine(*data);/* ikos: warning: pointer 'data' might be null */
}

/* goodB2G uses the BadSource with the GoodSink */
void goodB2GSink(map<int, int *> dataMap)
{
    int * data = dataMap[2];/* ikos: warning: pointer 'std::map<int, int*, std::less<int>, std::allocator<std::pair<int const, int*> > >::operator[](int&&)(&dataMap, &__unnamed_local_var)' might be null */
    /* FIX: Check for NULL before attempting to print data */
    if (data != NULL)
    {
        printIntLine(*data);
    }
    else
    {
        printLine("data is NULL");
    }
}

#endif /* OMITGOOD */

} /* close namespace */
