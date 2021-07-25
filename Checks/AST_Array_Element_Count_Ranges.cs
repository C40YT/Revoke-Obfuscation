using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class GroupedArrayElementRangeCounts
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // 返回 “数组类AST” 中元素个数的分布 包括数组数量范围的统计值与各个范围各自比例
        // Initialize Dictionary with common array count ranges initialized to 0.
        Dictionary<String, Double> astArrayElementCountsDictionary = new Dictionary<String, Double>(StringComparer.OrdinalIgnoreCase);
        
        astArrayElementCountsDictionary["0-10"] = 0;
        astArrayElementCountsDictionary["10-20"] = 0;
        astArrayElementCountsDictionary["20-30"] = 0;
        astArrayElementCountsDictionary["30-40"] = 0;
        astArrayElementCountsDictionary["40-50"] = 0;
        astArrayElementCountsDictionary["50-60"] = 0;
        astArrayElementCountsDictionary["60-70"] = 0;
        astArrayElementCountsDictionary["70-80"] = 0;
        astArrayElementCountsDictionary["80-90"] = 0;
        astArrayElementCountsDictionary["90-100"] = 0;
        astArrayElementCountsDictionary["UNKNOWN"] = 0;
        
        // Return all targeted AST objects by Count Ranges and Percent across the entire input AST object.
        return RevokeObfuscationHelpers.AstValueGrouper(ast, typeof(ArrayLiteralAst), astArrayElementCountsDictionary, "AstGroupedArrayElementRangeCounts",
            targetAst => { return ( ((int)((((ArrayLiteralAst) targetAst).Elements.Count / 10) * 10)).ToString() + "-" + (((int)((((ArrayLiteralAst) targetAst).Elements.Count / 10) * 10) + 10)).ToString() ); } );
    }
}