using System;
using System.Management.Automation;
using System.Management.Automation.Language;
using System.Collections;
using System.Collections.Generic;

public class CmdletMetrics
{
    public static IDictionary AnalyzeAst(Ast ast)
    {
        // 返回类型为CommandAst节点的命令项(选取每个CommandAst节点的CommandElements[0]值)中关于字符特征的统计
        // Build string list of all AST object values that will be later sent to StringMetricCalculator.
        List<String> stringList = new List<String>();
        
        foreach(CommandAst targetAst in ast.FindAll( testAst => testAst is CommandAst, true ))
        {
            // Extract the AST object value.
            // If InvocationOperator is "Unknown" then the cmdlet will be the first object in CommandElements (i.e. most likely a cmdlet like Invoke-Expression, Write-Output, etc.).
            // Otherwise it will be the name of the invocation operator.
            string cmdlet = null;
            if(targetAst.InvocationOperator.ToString() == "Unknown")
            {
                cmdlet = targetAst.CommandElements[0].Extent.Text;
            }
            else
            {
                // Convert InvocationOperator name to the operator value (using ? for UNKNOWN).
                switch(targetAst.InvocationOperator.ToString())
                {
                    case "Dot" : cmdlet = "."; break;
                    case "Ampersand" : cmdlet = "&"; break;
                    default : cmdlet = "?"; break;
                }
            }
            
            stringList.Add(cmdlet);
        }
        
        // Return character distribution and additional string metrics across all targeted AST objects across the entire input AST object.
        return RevokeObfuscationHelpers.StringMetricCalculator(stringList, "AstCmdletMetrics");
    }
}