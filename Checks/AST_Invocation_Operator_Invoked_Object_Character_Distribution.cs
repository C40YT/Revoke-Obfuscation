using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class InvocationOperatorInvokedObjectMetrics
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // invocation operator 举例子 & "1+1" 表示执行 1+1，其中CommandElements = {"1+1"}, 因此 CommandElements[0] = "1+1"
        // 分析invocation operator 中表达式所包含的字符特征
        // Build string list of all AST object values that will be later sent to StringMetricCalculator.
        List<String> stringList = new List<String>();

        foreach(CommandAst targetAst in ast.FindAll( testAst => testAst is CommandAst, true ))
        {
            // Extract the AST object value.
            if(targetAst.InvocationOperator.ToString() != "Unknown")
            {
                stringList.Add(targetAst.CommandElements[0].ToString());
            }
        }
        
        // Return character distribution and additional string metrics across all targeted AST objects across the entire input AST object.
        return RevokeObfuscationHelpers.StringMetricCalculator(stringList, "AstInvocationOperatorInvokedObjectMetrics");
    }
}