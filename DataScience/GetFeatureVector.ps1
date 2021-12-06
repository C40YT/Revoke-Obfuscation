# 首先要在执行环境中Import-Module Revoke-Obfuscation.psm1然后脚本中的Get-RvoFeatureVector才能使用
$labeledData = @{}
$bn = "C:\Users\caoyaotao\Desktop\final\PowerShellCorpus"
# InvokeCradleCrafter-obfuscation-labeledData.csv
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\InvokeCradleCrafter-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\InvokeObfuscation-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\IseSteroids-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\PoshCode-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\GithubGist-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\TechNet-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\UnderhandedPowerShell-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
# 在得到的csv结果中，如果Get-RvoFeatureVector报错则对应那行会是 ",1" 因此只需要排除这行即可

dir C:\Users\caoyaotao\Desktop\final\Revoke-Obfuscation\DataScience\UnderhandedPowerShell-obfuscation-labeledData.csv | % { Import-Csv $_.FullName | % { $labeledData[ (Join-Path $bn $_.path) ] = $_.Label } }
$analyzedCorpus = $labeledData.Keys | % {
    $scriptResult = ([PSCustomObject] (Get-RvoFeatureVector -Path $_)) | ConvertTo-CSV -NoTypeInformation | Select -Last 1
    $scriptResult += "," + $labeledData[$_]
    $scriptResult
}
$analyzedCorpus | Set-Content FeatureVector.csv