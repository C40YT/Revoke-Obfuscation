using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class TypeConstraintMetrics
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // 类型限制AST的字符统计
        // 比如 [int] 表示限制类型为int类型， 则stringList包含如 int 等
        // Build string list of all AST object values that will be later sent to StringMetricCalculator.
        List<string> stringList = new List<string>();
        
        foreach(TypeConstraintAst targetAst in ast.FindAll( testAst => testAst is TypeConstraintAst, true ))
        {
            // Extract the AST object value.
            string targetName = targetAst.Extent.Text;
            
            // Trim off the single leading and trailing square brackets of the Convert Expression type value.
            // Avoid using Trim so that square brackets will remain in select situations (e.g. [Char[]] --> Char[]).
            if(targetName.Length > 2)
            {
                stringList.Add(targetName.Substring(1,targetName.Length-2));
            }
            else
            {
                stringList.Add(targetName);
            }
        }
        
        // Return character distribution and additional string metrics across all targeted AST objects across the entire input AST object.
        return RevokeObfuscationHelpers.StringMetricCalculator(stringList, "AstTypeConstraintMetrics");
    }
}