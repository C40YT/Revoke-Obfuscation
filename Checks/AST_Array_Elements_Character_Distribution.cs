using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class ArrayElementMetrics
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // 返回 “数组类AST” items(选取每个数组类AST结点的Extent.Text值)中关于字符特征的统计
        // Build string list of all AST object values that will be later sent to StringMetricCalculator.
        List<String> stringList = new List<String>();

        foreach(Ast targetAst in ast.FindAll( testAst => testAst is ArrayLiteralAst, true ))
        {
            // Extract the AST object value.
            String targetName = targetAst.Extent.Text;
            
            stringList.Add(targetName);
        }
        
        // Return character distribution and additional string metrics across all targeted AST objects across the entire input AST object.
        return RevokeObfuscationHelpers.StringMetricCalculator(stringList, "AstArrayElementMetrics");
    }
}