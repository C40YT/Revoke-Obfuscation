using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class MemberMetrics
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // 对成员表达式Ast类的成员进行字符分析
        // 例如$sb.hahaha 成员为 hahaha，我们对hahaha等一众成员字符串进行字符分析
        // Build string list of all AST object values that will be later sent to StringMetricCalculator.
        List<string> stringList = new List<string>();
        
        foreach(MemberExpressionAst targetAst in ast.FindAll( testAst => testAst is MemberExpressionAst, true ))
        {
            // Extract the AST object value.
            stringList.Add(targetAst.Member.Extent.Text);
        }
        
        // Return character distribution and additional string metrics across all targeted AST objects across the entire input AST object.
        return RevokeObfuscationHelpers.StringMetricCalculator(stringList, "AstMemberMetrics");
    }
}