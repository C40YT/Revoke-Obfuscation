using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class MemberArgumentMetrics
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // 对方法调用中的参数(InvokeMemberExpressionAst.Arguments)进行字符分析(先用,进行拼接参数)
        // 例如$sb.append("abc", "efg")中体现为{"abc","efg"},加入stringList中的即为 "abc","efg"
        // Build string list of all AST object values that will be later sent to StringMetricCalculator.
        List<String> stringList = new List<String>();

        foreach(InvokeMemberExpressionAst targetAst in ast.FindAll( testAst => testAst is InvokeMemberExpressionAst, true ))
        {
            if(targetAst.Arguments != null)
            {
                // Extract the AST object value.
                stringList.Add(String.Join(",", targetAst.Arguments));
            }
        }
        
        // Return character distribution and additional string metrics across all targeted AST objects across the entire input AST object.
        return RevokeObfuscationHelpers.StringMetricCalculator(stringList, "AstMemberArgumentMetrics");
    }
}