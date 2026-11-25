/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE457_Use_of_Uninitialized_Variable__struct_array_alloca_no_init_63b.c
Label Definition File: CWE457_Use_of_Uninitialized_Variable.c_array.label.xml
Template File: sources-sinks-63b.tmpl.c
*/
/*
 * @description
 * CWE: 457 Use of Uninitialized Variable
 * BadSource: no_init Don't initialize data
 * GoodSource: Initialize data
 * Sinks: use
 *    GoodSink: Initialize then use data
 *    BadSink : Use data
 * Flow Variant: 63 Data flow: pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITBAD

void CWE457_Use_of_Uninitialized_Variable__struct_array_alloca_no_init_63b_badSink(twoIntsStruct * * dataPtr)
{
    twoIntsStruct * data = *dataPtr;
    /* POTENTIAL FLAW: Use data without initializing it */
    {
        int i;
        for(i=0; i<10; i++)
        {
            printIntLine(data[i].intOne);/* ikos: error: expression 'data[(int64_t)i].0' is uninitialized */
            printIntLine(data[i].intTwo);
        }
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE457_Use_of_Uninitialized_Variable__struct_array_alloca_no_init_63b_goodG2BSink(twoIntsStruct * * dataPtr)
{
    twoIntsStruct * data = *dataPtr;
    /* POTENTIAL FLAW: Use data without initializing it */
    {
        int i;
        for(i=0; i<10; i++)
        {
            printIntLine(data[i].intOne);/* ikos: warning: expression 'data[(int64_t)i].0' might be uninitialized */
            printIntLine(data[i].intTwo);/* ikos: warning: expression 'data[(int64_t)i].1' might be uninitialized */
        }
    }
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE457_Use_of_Uninitialized_Variable__struct_array_alloca_no_init_63b_goodB2GSink(twoIntsStruct * * dataPtr)
{
    twoIntsStruct * data = *dataPtr;
    /* FIX: Ensure data is initialized before use */
    {
        int i;
        for(i=0; i<10; i++)
        {
            data[i].intOne = i;
            data[i].intTwo = i;
        }
    }
    {
        int i;
        for(i=0; i<10; i++)
        {
            printIntLine(data[i].intOne);/* ikos: warning: expression 'data[(int64_t)i].0' might be uninitialized */
            printIntLine(data[i].intTwo);/* ikos: warning: expression 'data[(int64_t)i].1' might be uninitialized */
        }
    }
}

#endif /* OMITGOOD */
