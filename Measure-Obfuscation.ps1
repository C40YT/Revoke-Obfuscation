param (
    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Csv')]
    [System.String[]]
    $Csv,

    [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'File')]
    [System.String[]]
    $File
)


# 通过Get-RvoFeatureVector得到脚本对应的特征，通过Measure-Vector计算得到混淆的分数和是否混淆的判断
# 其中Get-RvoFeatureVector调用了checks下的方法进行特征计算
# 而Measure-Vector则是利用在DataSience目录下训练得到的权重
function Measure-RvoObfuscation
{
<#
.SYNOPSIS

Measure-RvoObfuscation orchestrates the feature vector extraction, whitelist comparisons, and obfuscation measurements for input script path (or URL), expression, script block, or Get-RvoScriptBlock result or results. Results are returned as an array of PSCustomObjects containing the input script and additional metadata (whitelisted, obfuscated, contents hash, etc.).

Revoke-Obfuscation Function: Measure-RvoObfuscation
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: Check-Whitelist, Get-RvoFeatureVector, Measure-Vector, .\Requirements\CommandLine\Convert-PowerShellCommandLine.ps1
Optional Dependencies: None

.DESCRIPTION

Measure-RvoObfuscation orchestrates the feature vector extraction, whitelist comparisons, and obfuscation measurements for input script path (or URL), expression, script block, or Get-RvoScriptBlock result or results. Results are returned as an array of PSCustomObjects containing the input script and additional metadata (whitelisted, obfuscated, contents hash, etc.).

.PARAMETER Url

Specifies the URL(s) to the PowerShell script to measure for obfuscation.

.PARAMETER Path

Specifies the path(s) to the PowerShell script to measure for obfuscation.

.PARAMETER LiteralPath

Specifies the literal path to the PowerShell script to measure for obfuscation. Wildcards are not supported, and are treated as path characters.

.PARAMETER ScriptExpression

Specifies the PowerShell script expression(s) to measure for obfuscation.

.PARAMETER ScriptBlock

Specifies the PowerShell script block(s) to measure for obfuscation.

.PARAMETER GetRvoScriptBlockResult

Specifies the Get-RvoScriptBlockResult reassembled script block result(s) to measure for obfuscation.

.PARAMETER WhitelistFile

(Optional) Specifies file or list of files (supports wildcarding) to whitelist by file hash during current function invocation.

.PARAMETER WhitelistContent

(Optional) Specifies string or list of strings to whitelist during current function invocation.

.PARAMETER WhitelistRegex

(Optional) Specifies regex or list of regexes to whitelist during current function invocation.

.PARAMETER Deep

(Optional) Specifies that the deeper (but lower confidence) weighted vector be used (in Measure-Vector function) to measure input vector, thus a "deep" inspection that will allow more False Positives but fewer False Negatives than the default high confidence weighted vector.

.PARAMETER CommandLine

(Optional) Specifies that the command-specific (as opposed to the default script-specific) weighted vector be used (in Measure-Vector function) to measure input vector.

.PARAMETER OutputToDisk

(Optional) Outputs obfuscated results to disk at "$resultObfuscatedDir\$hash.ps1" where the $resultObfuscatedDir variable is defined at the end of Revoke-Obfuscation.psm1.

.EXAMPLE

C:\PS> $obfResults = Measure-RvoObfuscation -Url 'http://bit.ly/DBOdemo1' -Verbose

.EXAMPLE

C:\PS> $obfResults = Measure-RvoObfuscation -Path .\Demo\DBOdemo1.ps1 -Verbose

.EXAMPLE

C:\PS> $obfResults = Get-Content -Path .\Demo\DBOdemo1.ps1 -Raw | Measure-RvoObfuscation -Verbose -OutputToDisk

.EXAMPLE

C:\PS> $obfResults = Get-WinEvent Microsoft-Windows-PowerShell/Operational -FilterXPath {*[System[(EventID=4104)]]} | Get-RvoScriptBlock | Measure-RvoObfuscation -Verbose -OutputToDisk

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    [CmdletBinding(DefaultParameterSetName = 'Path')] 
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Url')]
        [Alias('Uri')]
        [System.Uri[]]
        $Url,
        
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = 'Path')]
        [Alias('File')]
        [System.String[]]
        $Path,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'LiteralPath')]
        [Alias('PSPath')]
        [System.String]
        $LiteralPath,

        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ScriptExpression')]
        [Alias('Expression','ScriptContent')]
        [System.String[]]
        $ScriptExpression,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ScriptBlock')]
        [ScriptBlock[]]
        $ScriptBlock,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'GetRvoScriptBlockResult')]
        [PSTypeName("RevokeObfuscation.RvoScriptBlockResult")]
        $GetRvoScriptBlockResult,
        
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $WhitelistFile,
        
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $WhitelistContent,
        
        [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
        [System.String[]]
        $WhitelistRegex,
        
        [Parameter(Mandatory = $false)]
        [Switch]
        $Deep,
        
        [Parameter(Mandatory = $false)]
        [Switch]
        $CommandLine,

        [Parameter(Mandatory = $false)]
        [Switch]
        $OutputToDisk
    )
    
    begin
    {
        # Generate hashes for all scripts/paths defined in the -WhitelistFile argument and add as whitelisted scripts for this current invocation.
        $script:whitelistArgHashArray = @()
        if ($WhitelistFile)
        {
            # Iterate through each script/path defined in the -WhitelistFile argument.
            foreach ($inputFilePath in $WhitelistFile)
            {
                # Resolve file(s) from current $inputFilePath if they exist.
                Try
                {
                    $filesToWhitelist = $PSCmdlet.GetResolvedProviderPathFromPSPath($inputFilePath, [ref] $null)
                }
                Catch
                {
                    $filesToWhitelist = $null
                }

                # Compute hash for each file resolved from current input file path and add hash to $script:whitelistArgHashArray (NOT $script:whitelistHashArray).
                foreach ($file in $filesToWhitelist)
                {
                    # Read in file for hashing to maintain parity with scripts ingested through non-file means (like from event logs).
                    $scriptContent = Get-Content -Path $file -Raw

                    # Compute hash for $file's raw contents.
                    $ms = New-Object System.IO.MemoryStream
                    $sw = New-Object System.IO.StreamWriter $ms
                    $sw.Write($scriptContent)
                    $sw.Flush()
                    $sw.BaseStream.Position = 0
                    $hash = (Get-FileHash -InputStream $sw.BaseStream -Algorithm SHA256).Hash
                
                    # Add hash to $script:whitelistArgHashArray as a PSCustomObject for later comparisons in Check-Whitelist function.
                    $script:whitelistArgHashArray += , [PSCustomObject] @{
                        Name  = [System.String] $file
                        Value = [System.String] $hash
                    }
                }
            }
        }

        # Add all strings defined in the -WhitelistContent argument and add as whitelisted strings for this current invocation.
        $script:whitelistArgStringArray = @()
        if ($WhitelistContent)
        {
            foreach ($whitelistString in $WhitelistContent)
            {
                # Add result to $script:whitelistArgStringArray as a PSCustomObject for later comparisons in Check-Whitelist function.
                $script:whitelistArgStringArray += , [PSCustomObject] @{
                    Name  = [System.String] 'Defined via -WhitelistContent arg'
                    Value = [System.String] $whitelistString
                }
            }
        }

        # Add all strings defined in the -WhitelistRegex argument and add as whitelisted regex terms for this current invocation.
        $script:whitelistArgRegexArray = @()
        if ($WhitelistRegex)
        {
            foreach ($whitelistRegex in $WhitelistRegex)
            {
                # Add result to $script:whitelistArgRegexArray as a PSCustomObject for later comparisons in Check-Whitelist function.
                $script:whitelistArgRegexArray += , [PSCustomObject] @{
                    Name  = [System.String] 'Defined via -WhitelistRegex arg'
                    Value = [System.String] $whitelistRegex
                }
            }
        }
        
        # Array that will house single or multiple input scripts that will be evaluated.
        $scriptContentArray = @()
    }
    
    process
    {
        # Handle various input formats to produce the same data format in the $scriptContent variable for calculating SHA256 hash.
        switch ($PSCmdlet.ParameterSetName)
        {
            "Url" {
                # Read in Url(s) as an expression.
                foreach ($curUrl in $Url)
                {
                    $scriptContentArray += [PSCustomObject] @{
                        Source = $curUrl
                        Content = (Invoke-WebRequest ([System.Uri] $curUrl)).Content
                    }
                }
            }
            "Path" {
                # Read in file path(s) as an expression.
                foreach ($curPath in $executionContext.SessionState.Path.GetResolvedProviderPathFromProviderPath($Path, 'FileSystem'))
                {
                    $scriptContentArray += [PSCustomObject] @{
                        Source = $curPath
                        Content = Get-Content -Path $curPath -Raw
                    }
                }
            }
            "LiteralPath" {
                # Read in file path(s) as an expression.
                $scriptContentArray += [PSCustomObject] @{
                    Source = (Get-Item -LiteralPath $LiteralPath).FullName
                    Content = Get-Content -LiteralPath $LiteralPath -Raw
                }
            }

            "ScriptExpression" {
                # Cast each ScriptExpression as a string.
                foreach ($curScriptExpression in $ScriptExpression)
                {
                    # If a single URL string is passed to this function via the pipeline then it will be interpreted as a ScriptExpression, so throw a warning for this scenario.
                    if ($curScriptExpression.StartsWith('http'))
                    {
                        Write-Warning "Input looks like a URL but is being interpreted as a ScriptExpression.`n         If it is an URL then specify the -Url flag or cast value to [System.Uri[]]."
                    }

                    $scriptContentArray += [PSCustomObject] @{
                        Source = "<Direct>"
                        Content = [System.String] $curScriptExpression
                    }
                }
            }

            "GetRvoScriptBlockResult" {
                # Extract ScriptBlock property from each curGetRvoScriptBlockResult object.
                foreach ($curGetRvoScriptBlockResult in $GetRvoScriptBlockResult)
                {
                    $scriptContentArray += [PSCustomObject] @{
                        Source = $curGetRvoScriptBlockResult
                        Content = [System.String] $curGetRvoScriptBlockResult.ScriptBlock
                    }
                }
            }

            "ScriptBlock" {
                # Cast each ScriptBlock as a string.
                foreach ($curScriptBlock in $ScriptBlock)
                {
                    $scriptContentArray += [PSCustomObject] @{
                        Source = $curScriptBlock
                        Content = [System.String] $curScriptBlock
                    }
                }
            }
        }
    }

    end
    {
        # Iterate through each $scriptContent value in $scriptContentArray and return the resultant array of PSCustomObject values.
        $counter = 0
        $totalCount = $scriptContentArray.Count
        return $scriptContentArray | ForEach-Object {
            
            $source = $_.Source
            $scriptContent = $_.Content
            
            # If -CommandLine switch is selected then clean up the arguments for proper feature extraction and measurement.
            if ($CommandLine.IsPresent)
            {
                # Clean up the command line formatting for powershell.exe like decoding encoded commands, replacing -command "whole command goes here" with -command { whole command goes here }, etc.
                $scriptContent = . $scriptDir\Requirements\CommandLine\Convert-PowerShellCommandLine.ps1 $scriptContent
            }
            
            $counter++

            # Compute hash for input $scriptContent.
            $ms = New-Object System.IO.MemoryStream
            $sw = New-Object System.IO.StreamWriter $ms
            $sw.Write($scriptContent)
            $sw.Flush()
            $sw.BaseStream.Position = 0
            $hash = (Get-FileHash -InputStream $sw.BaseStream -Algorithm SHA256).Hash

            # Check if input $scriptContent matches any of the whitelisting options (SHA256 hash match, content match, or regex match).
            [System.Timespan] $checkTime = Measure-Command { $whitelistResult = Check-Whitelist -ScriptContent $scriptContent -Hash $hash }

            # 如果文件和白名单的符合，则直接表示非混淆
            if ($whitelistResult.Match)
            {
                if ($PSBoundParameters.Verbose)
                {
                    Write-Host "[$counter of $totalCount] WHITELISTED    :: " -NoNewline -ForegroundColor Green
                    Write-Host "($hash)" -ForegroundColor White
                }

                # Set $measureTime to zero since no vector measurement will be performed for whitelisted input.
                $measureTime = [System.Timespan]::Zero

                # Set remaining variables to default values for whitelisted content so they can be added to resultant PSCustomObject after this if block.
                $obfuscated = $false
                $obfuscatedScore = [System.Double] 0.0
                $resultFile = "No Result File"
            }
            else
            {
                # 不属于白名单中的文件，通过Get-RvoFeatureVector得到脚本对应的特征，通过Measure-Vector计算得到混淆的分数和是否混淆的判断
                # Not whitelisted so we will proceed with extracting features and then measuring these features against specified weighted vector.

                # Scrape features from input $scriptContent, storing the time in $checkTime.
                [System.Timespan] $checkTime = Measure-Command { $scriptFeatures = Get-RvoFeatureVector -ScriptExpression $scriptContent }
                
                # Measure features vector scraped from input $scriptContent, storing the time in $measureTime.
                [System.Timespan] $measureTime = Measure-Command { $vectorMeasurement = Measure-Vector -FeatureVector $scriptFeatures -Deep:$Deep -CommandLine:$CommandLine }
                
                # Set obfuscated values in variable so they can be added to resultant PSCustomObject after this else block.
                $obfuscated = $vectorMeasurement.Obfuscated
                $obfuscatedScore = $vectorMeasurement.ObfuscatedScore

                if ($obfuscated)
                {
                    if ($PSBoundParameters.Verbose)
                    {
                        Write-Host "[$counter of $totalCount] OBFUSCATED     :: " -NoNewline -ForegroundColor Red
                        Write-Host "($hash)" -ForegroundColor White
                    }

                    # If -OutputToDisk flag was selected then output obfuscated script(s) to $resultObfuscatedDir.
                    if ($OutputToDisk)
                    {
                        # Create results directory if it does not exist.
                        if (-not (Test-Path $resultObfuscatedDir))
                        {
                            New-Item -ItemType Directory -Path $resultObfuscatedDir -Force
                        }
                        
                        $resultFile = "$resultObfuscatedDir\$hash.ps1"
                        Set-Content -Path $resultFile -Value $scriptContent -NoNewline
                    }
                    else
                    {
                        $resultFile = "No Result File (-OutputToDisk flag not set)"
                    }
                }
                else
                {
                    $resultFile = "No Result File"

                    if ($PSBoundParameters.Verbose)
                    {
                        Write-Host "[$counter of $totalCount] NOT OBFUSCATED :: " -NoNewline -ForegroundColor Green
                        Write-Host "($hash)" -ForegroundColor White
                    }
                }
            }

            # Return result as a PSCustomObject.
            [PSCustomObject] @{
                PSTypeName      = "RevokeObfuscation.Result"
                ScriptContent   = [System.String] $scriptContent
                Hash            = [System.String] $hash
                Source          = [System.String] $source
                Obfuscated      = [System.Boolean] $obfuscated
                ObfuscatedScore = [System.Double] $obfuscatedScore
                ResultFile      = [System.String] $resultFile
                CheckTime       = [System.Timespan] $checkTime
                MeasureTime     = [System.Timespan] $measureTime
                Whitelisted     = [System.Boolean] $whitelistResult.Match
                WhitelistResult = [PSCustomObject] $whitelistResult
                ScriptFeatures  = [System.Collections.Specialized.OrderedDictionary] $scriptFeatures
            }
        }
    }
}

# 通过脚本特征向量和权重向量得到脚本的混淆程度，返回是否混淆和混淆分数
function Measure-Vector
{
<#
.SYNOPSIS

Measure-Vector compares input feature vector against weighted vector ($weightedVector) computed during the training phase using ModelTrainer.cs/ModelTrainer.exe. Measure-Vector returns a PSCustomObject with a boolean and double containing information detailing the obfuscation level for the input feature vector.

Revoke-Obfuscation Helper Function: Measure-Vector
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Measure-Vector compares input feature vector against weighted vector ($weightedVector) computed during the training phase using ModelTrainer.cs/ModelTrainer.exe. Measure-Vector returns a PSCustomObject with a boolean and double containing information detailing the obfuscation level for the input feature vector.

.PARAMETER FeatureVector

Specifies the feature vector generated from the Get-RvoFeatureVector function to measure the obfuscation of the current script.

.PARAMETER Deep

(Optional) Specifies that the deeper (but lower confidence) weighted vector be used to measure input vector, thus a "deep" inspection that will allow more False Positives but fewer False Negatives than the default high confidence weighted vector.

.PARAMETER CommandLine

(Optional) Specifies that the command-specific (as opposed to the default script-specific) weighted vector be used to measure input vector.

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'FeatureVector')]
        [System.Collections.Specialized.OrderedDictionary]
        $FeatureVector,

        [Parameter(Mandatory = $false)]
        [Switch]
        $Deep,
        
        [Parameter(Mandatory = $false)]
        [Switch]
        $CommandLine
    )
    
    # 权重1
    # Weighted feature vector generated from ModelTrainer.cs/ModelTrainer.exe during the training phase.
    <#
        Accuracy: 0.8926
        Precision: 0.8977
        Recall: 0.8849
        F1Score: 0.8913
        TruePositiveRate: 0.4403
        FalsePositiveRate: 0.0502
        TrueNegativeRate: 0.4523
        FalseNegativeRate: 0.0573
    #>
    [System.Double[]] $broadNetWeightedVector = @(-17.1724, 235.1034, 104.4230, 3873.9960, -1191.7707, 994.6969, 26.4900, -3759.5441, 590.1402, -167.2932, -21.4097, 91.6150, -40.4320, 1418.6049, 392.1263, 1429.8980, 416.3834, -1351.5963, -1413.1739, 678.6298, 2501.3818, 1144.5008, -896.3403, -4128.0906, -323.0181, -1128.3312, -183.7754, 1146.3584, 32.4313, 523.3502, 325.6972, -521.9330, -220.3967, 1249.6883, 718.9515, 2512.4248, -773.1501, 1237.3477, 668.7407, -99.7097, -398.5389, -694.4784, -24.3991, 642.5583, -390.5068, -6017.9056, -646.8041, 136.5016, 443.3714, -247.4458, 267.3194, -91.1520, -143.3763, -281.1458, 264.4011, 61.3900, 13.2439, 1285.2800, 286.0907, 179.9621, 199.5689, 184.2626, 110.5004, 308.9928, 320.0361, 1963.4815, -55.4143, -797.0728, 284.0825, -1745.0952, -477.0053, -1634.3830, 843.9432, -3109.8843, 546.9212, -1638.3744, 266.4324, -1362.8492, -125.4458, -866.1689, 692.4512, -2641.6017, 348.7146, -1967.4660, -52.3131, 1918.7961, 462.3851, 34.8981, 762.4477, 0.0000, 0.0000, -2335.9437, 223.1447, -396.1092, 132.9381, 0.0000, 0.0000, 0.0000, 0.0000, -1654.1310, 554.0345, -1109.4660, -244.5864, 0.0000, 0.0000, 709.4650, -838.3841, -5167.7016, -778.6296, 3439.8801, -902.8284, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1812.3136, 315.2598, -3861.5247, -670.7899, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1615.3146, 1218.6536, 563.7364, -4.8425, 0.0000, 0.0000, 0.0000, 0.0000, 463.5691, -436.7878, 2639.2801, 198.3113, 0.0000, 0.0000, -235.8287, 173.7055, 866.5437, -441.4560, 1041.8079, -406.0748, -528.4374, -1270.8966, 276.9613, 175.5449, 819.4549, 112.0146, 617.2530, -203.6312, -211.0814, -322.5973, -672.3365, 19.0805, 301.7578, -1160.8385, 1294.6441, -901.9809, 3623.0302, 430.3532, 325.2071, -434.7205, 416.4465, 461.6046, 2744.1347, -271.7808, 0.0000, 0.0000, 0.0000, 0.0000, 326.3654, 766.9754, 1983.3219, -1936.9814, 2029.3121, -83.9053, -342.8305, -425.9973, 188.4605, 10.8088, 181.8634, -486.1530, 1341.7306, 210.4124, 1107.5781, 724.0924, 0.0000, 0.0000, 158.8701, 1487.9097, -2686.6880, 1560.1373, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 427.1092, -4404.8223, -10.1400, -3.8120, -27.4650, -6.8783, 0.0000, 0.0000, 0.0000, 0.0000, 42.3549, 2.0037, 27.7777, 29.4165, 18.8627, 1.3657, 0.8550, 0.5856, 0.0000, 0.0000, -22.4300, -8.0627, -7.3950, -1.4022, 25.7100, 3.2630, 1723.3365, 8.0770, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -815.2315, -236.7299, 2782.9928, 397.5813, -2237.0604, -881.3701, 1397.4441, 366.8427, 1611.8308, -798.6290, 119.2052, -184.2231, 0.0000, 0.0000, 0.0000, 0.0000, 240.7919, -749.3985, -1174.5833, 89.9519, 0.0000, 0.0000, 471.9959, -275.5085, -604.2442, -472.5019, 18.3891, 67.7129, 61.9969, 851.2725, 839.7959, 98.8854, 1761.2869, 1757.9920, 730.5300, 0.3125, 139.8017, 8.9340, -77.8232, 16.2582, -15.7408, 13.0297, 29.4962, -8.7424, -45.2370, -86.3606, -202.8407, -356.8967, 117.6518, -318.5214, -320.4925, 1556.2693, -669.6853, 107.4970, -1155.1648, 206.4668, 485.4795, -348.0355, 91.8976, 116.1507, 42.8012, 89.1068, 44.4321, 27.0439, -22.7987, 111.8526, 1.7399, 38.9750, -57.1450, -2048.6398, -14.5522, -1679.2942, -6.1650, -558.8152, 7.5679, 169.3087, 6.2200, 504.3315, 0.0700, 1.6167, 1.4200, 47.9905, 0.0350, 3.0714, 5.7850, 124.9066, 31.4650, 151.7762, -163.4773, 412.2284, 122.2155, 1242.6552, 61.9600, 706.1614, 2280.0903, -97.1060, 77.1295, 367.2835, 0.0000, 0.0000, 1102.8401, 84.9302, -77.8232, -191.4440, 2409.3830, -182.4392, 0.0000, 0.0000, 0.0000, 0.0000, 1250.5311, 160.3500, 0.0000, 0.0000, 140.1166, 43.3334, 0.0000, 0.0000, 2641.1704, 1577.8652, 0.2100, 0.1400, 966.0157, -129.9838, -756.9089, -147.6556, 743.0668, 419.4867, 0.0000, 0.0000, 0.0000, 0.0000, -212.6935, -12.7160, -528.9602, -2029.6415, 0.0000, 0.0000, 27.3591, -0.7784, -1813.8997, 135.9891, -281.5181, 9.0601, 940.2963, 643.8929, 46.4850, 10.9533, 188.6900, 40.5715, 68.8814, 3.4078, 292.4982, 44.2070, -58.7512, 120.8759, 68.6063, 426.0356, -145.1457, -98.4720, -1136.4319, -581.7889, 0.0000, 0.0000, -157.2223, 210.5357, -637.8218, -938.5154, -142.8530, 104.9497, 1464.2824, 515.0247, 229.8003, 36.6224, 1007.2043, -318.2981, 24.3861, 446.3239, -1440.5427, 33.0349, -2344.1640, -213.0947, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 854.4810, 1326.9584, 28.7800, 14.6159, -3567.3841, -121.5234, -2913.5576, 151.9471, -246.3271, 19.7053, -1064.2076, -790.2918, 2830.4938, 2351.5516, 890.9803, 441.6812, 0.0000, 0.0000, 452.4100, 141.2623, 0.0000, 0.0000, -1278.1095, -149.2897, -1810.8839, -6.6439, -3257.9968, -381.9958, 0.0000, 0.0000, 0.0000, 0.0000, -37.0783, -820.3731, 149.5946, -1042.9793, -694.4654, -592.0909, 373.1140, 96.0288, 419.0807, -82.2199, -178.4837, -36.7567, -377.9141, -115.7126, 204.5340, -414.0622, 60.6363, 1.4674, 1739.3837, 120.3226, -395.5717, 967.4886, 0.0000, 0.0000, -4.9350, -5.3013, 0.1400, 0.0365, -805.4655, -2946.4698, -34.2439, -67.0788, -530.0074, -1602.2974, -341.9626, -233.9226, 177.4112, -1115.0737, -104.6850, -1784.9191, -53.3860, -681.0558, 0.0000, 0.0000, -4.1450, -29.0563, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0800, 5.3333, 0.0000, 0.0000, 45.1150, 818.6624, -9.8900, -58.4706, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.1900, -15.0769, 97.0600, 1058.0391, 0.0000, 0.0000, 1008.2318, -225.0598, 346.6273, 24.4219, 453.4705, -591.5961, -79.5023, -3353.3907, 99.8074, -254.3070, 92.6723, 88.8088, -11.4212, -980.9646, -13.4049, -28.1424, 101.5259, 1446.2790, 765.6557, 82.3247, -264.0703, 6.6994, 267.1178, 32.9153, -615.1291, -593.6581, 404.5328, 587.8215, -9.1183, -229.1456, 812.5641, 250.4850, -96.9707, -790.5561, 724.2059, -1255.7262, -553.9234, -981.3078, -181.1279, -1726.7703, 129.7756, -357.4059, -45.3671, 109.8189, -298.7686, -212.9561, 355.1156, 33.2371, -414.6460, -1601.0156, 627.1285, -188.5388, -88.6063, -1982.5508, 0.1750, 0.3477, 2.1100, 3.1029, -153.5900, -902.3639, 0.3200, 0.1561, 31.6850, 8.5079, -1250.0799, 84.2671, 18.6647, 56.4256, -24.3030, -1033.1777, 83.2019, 57.7270, -129.3070, -1504.6286, -100.5000, 13.6378, -125.3450, 5.9381, 726.9187, 1303.8363, 22.3150, 22.3098, -1744.9911, 385.1884, 162.5748, 98.8774, 2630.5406, 5.9777, 9.0500, 50.7148, 277.4144, -874.9041, -351.5985, 377.0070, -479.0016, 322.0070, -931.0636, 189.3118, -623.6375, 237.2761, -5.0700, -2.7112, 2433.0871, 595.9698, -164.2118, -51.6452, -2451.1127, -2193.8236, 5449.1256, 2285.5855, -42.8500, 17.3006, -20.8150, -6.9671, -32.7600, 19.6625, -0.1202, -5.2577, -804.5000, -33.4413, 372.0893, -16.0325, 106.3552, 245.1948, -140.4543, 61.4570, 733.5617, -153.1263, 309.1287, -71.8322, 1421.3139, 100.8351, 652.4829, 16.7993, 343.1833, -107.4604, 404.6667, 21.8614, 699.6403, 182.5750, 388.7418, -33.1040, 325.1368, -16.3658, 474.2350, -18.9166, -2755.5267, -1588.1196, 51.6311, -17.0933, 0.0000, 0.0000, -475.1474, 72.0762, 2194.7859, 325.5768, 0.0000, 0.0000, 0.0000, 0.0000, 678.4658, 67.1219, -181.3761, -697.7242, 0.0000, 0.0000, -398.3450, 10.2240, -1371.5496, 752.2924, -3193.5964, -646.3509, 0.0300, 0.1579, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0300, 0.1579, 30.7026, -169.8657, 620.0029, -215.1865, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -606.5820, -321.1601, -404.7517, 1212.4277, 0.0000, 0.0000, 0.0000, 0.0000, -502.6514, -549.9810, -1804.4701, -332.3914, 0.0000, 0.0000, 2152.9319, -580.2922, -305.5524, 1355.8962, 1946.9341, -342.4509, 59.3881, -336.3058, 337.9434, 585.7099, -386.0937, -724.0776, -96.7649, 180.7062, 129.1866, -828.6859, -2732.2131, -244.5616, 1258.0916, 1135.5964, -219.1450, 50.6358, -53.3086, 890.4131, 1382.5038, -85.8022, -371.9968, -462.4919, -361.6988, -801.2467, 0.0000, 0.0000, 0.1000, 7.7237, 146.1460, -267.4926, -0.7756, -1499.3415, 505.5944, -1644.6843, -1065.9998, 296.5120, -210.1338, -2.8147, -159.9458, 95.2547, 286.2650, 188.4551, 2694.3140, 450.0357, 0.0000, 0.0000, 1139.7230, -969.4653, -375.4737, -2061.0502, 0.0000, 0.0000, 0.0000, 0.0000, -0.3900, -0.5652, -3659.0409, 252.1908, 1.3750, 4.8229, -9.5400, -1.4515, 0.0000, 0.0000, 0.0000, 0.0000, 27.5750, 8.8502, 85.7900, 36.2912, -84.2500, -39.5089, -14.5600, 1.1369, 0.0000, 0.0000, -111.0700, -15.9513, 1.9500, 2.2674, -29.4400, -4.7423, 1568.1387, 450.1314, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 696.5610, -334.1767, -1501.9837, -1654.9811, -114.9000, -24.0630, -908.7945, -235.3991, 951.4409, 624.1899, -802.4174, -280.8721, 0.0000, 0.0000, 0.0000, 0.0000, 3419.9914, 230.8968, 277.6414, 297.5974, 0.0000, 0.0000, 635.9902, 309.1785, 95.1719, -1327.2663, -394.5371, -118.3872, -1722.2442, 181.8291, -110.2381, 20.5506, -2688.2739, -672.6700, -56.8450, -50.9396, -584.2170, -815.9068, 743.0668, -107.9316, -106.6514, -106.6514, -106.0386, -106.6514, -0.6127, -266.1567, -254.2659, -400.6617, -328.6174, 19.0166, 74.3515, 1814.9535, 43.8222, -318.2227, 801.6709, -517.1933, -757.8487, -364.1911, -52.2505, -169.5305, -25.2104, 30.8085, -50.2938, -200.3390, -57.3950, -7.0373, -323.5300, -60.9306, 0.0000, 0.0000, 540.1600, 199.0138, -9.3800, -0.8294, 0.0000, 0.0000, -118.5750, -26.9359, -118.5750, -26.9359, 2.6350, 0.2806, -12.9950, -5.5213, -96.3900, -118.4396, -25.0150, -5.5364, 259.1052, 167.5547, 0.0000, 0.0000, -1.0300, -453.9262, 0.1500, 0.1339, 7.0000, -7.8628, 36.2400, 54.1079, 7.0000, -7.8628, 0.0000, 0.0000, -74.4498, -19.4433, 11.9500, -19.4350, -300.3019, 88.3640, -38.9450, -15.5683, 4.3250, 2.4042, 0.0000, 0.0000, 4.3250, 2.4042, 0.0000, 0.0000, 0.7100, -0.6992, 0.0000, 0.0000, 18.1100, 8.6362, 0.0000, 0.0000, -71.7450, -14.4856, 103.4950, -4.2954, -83.2500, -23.4627, -20.3150, -11.8291, 0.5908, 7.3359, -4.9300, -1.9634, -0.9050, -0.1478, -49.9300, -15.0064, -63.1450, -3.3542, 0.1400, 5.4869, -884.4385, -940.9863, 242.1491, 270.6027, 0.0000, 0.0000, 1566.3430, -72.3596, 71.3036, -35.5346, 0.0000, 0.0000, 0.0000, 0.0000, 2510.3756, -131.6241, -737.7590, -1280.3958, 0.0000, 0.0000, 0.0000, 0.0000, -1154.5312, -1262.6698, 31.7784, 514.4178, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -623.5873, -732.9509, 1602.4276, 1222.0570, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 2744.3853, 1023.1945, -2641.9119, -1690.6526, 0.0000, 0.0000, 0.0000, 0.0000, -623.1673, -322.3472, 5080.8387, -637.3101, 0.0000, 0.0000, 775.7671, -630.2504, 861.6526, 295.5756, -967.7668, 599.2325, -741.5462, 1474.0438, -88.4962, -66.7953, 78.4289, -446.2652, 260.9332, -37.8483, 2109.3234, 1040.2678, 563.0167, 312.8316, 413.1188, -865.5207, 0.0000, 0.0000, 809.1982, 1480.9431, -2186.5072, 556.2069, -502.5453, 757.0148, -888.9373, 2207.8303, 0.0000, 0.0000, 0.0000, 0.0000, -257.4706, -652.4513, 2924.7235, -948.7097, -332.8283, 1024.8986, -1768.7026, -631.9781, -508.6598, -518.0717, -210.6495, -124.2263, 201.6254, -668.3509, -1294.4470, 263.4060, 0.0000, 0.0000, -205.2332, 407.5230, -100.8237, 209.4196, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -79.2550, 50.2280, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -284.8716, -254.0642, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -640.7713, 459.2831, -332.8421, -999.8315, 0.0000, 0.0000, 516.1907, -65.4660, -1499.1504, 285.9561, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -169.0067, -798.4503, -813.6788, 1507.5398, 0.0000, 0.0000, 171.2823, -84.7849, -751.9421, -399.3873, -33.9150, -227.4101, -1045.4334, -136.8096, -0.9799, -68.9803, -808.4468, 1136.2279, 50.7553, 317.5971, -21.4933, 470.2160, -528.9602, 20.3116, 20.9231, 20.9231, 19.7581, 20.9231, 1.1650, -35.0674, 157.1554, -5.8547, -28.5284, -60.9616, 185.6837, -920.7879, 49.6869, -1038.4374, 219.3710, -1453.6253, -169.6841, 193.8281, -27.7764, -16.3521, -27.0982, -48.7625, -45.6136, 32.4104, -299.8265, -8.5003, -882.0814, -24.8766, -1574.3841, 2243.6810, 217.1575, 266.1718, -370.5665, -22.9647, 1633.3505, 70.6399, -850.8165, 1.6354, -414.5928, -0.7709, -344.2284, 59.3626, 0.0089, 60.0908, -1859.6184, -464.5052, -2093.1888, -316.5817, -903.4701, -498.8354, 1579.5295, 60.5161, 517.6252, -20.8773, -312.4541, -113.6620, -510.3490, 35.8649, -281.0767, -570.6335, -726.5062, 16.5359, -18.1104, -10.8897, 2751.9634, -497.0755, 517.8292, -215.1845, 941.0806, 1364.6021, -1146.4348, 9.2968, 2218.9004, -63.6821, -1058.0877, -193.4777, 2183.6712, -80.1232, -1042.4040, 321.5503, 430.3434, -385.2934, 3047.2692, 180.0198, 563.1859, -3934.8607, 3060.9345, 186.9719, 3749.6947, 175.9939, -3252.6125, -130.2694, 1136.7121, -167.9099, -76.4562, -38.1038, -580.6500, -80.8212, -401.3878, 317.3922, -1639.7636, -229.1655, -798.4376, 123.5828, 1041.3200, 0.3641, -633.6203, 76.3362, 253.4127, -220.0134, 1769.5031, -2699.1115, 0.0000, 0.0000, 1168.7740, -43.8396, 3781.2542, -1208.4781, 0.0000, 0.0000, 0.0000, 0.0000, 519.3734, 653.5817, 189.2568, 1274.0173, 0.0000, 0.0000, 1138.3575, -186.6831, 3273.4685, 295.7946, 241.4246, -398.3549, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 346.1530, 45.5811, 728.5833, -637.8593, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1.3500, -0.6279, 718.5113, 286.1761, 1366.6063, 272.3945, 0.0000, 0.0000, 0.0000, 0.0000, 1163.6929, 282.3897, 239.8096, -433.3792, 0.0000, 0.0000, -1196.9790, -180.8338, -136.1073, 525.0628, -3353.4995, -118.7819, 3671.3230, 410.3542, 624.6236, 20.9198, 2398.6915, -9.2369, -1017.9001, 14.3975, -513.7474, -501.5440, 2009.8416, 90.2515, -3288.4562, 502.1571, 148.3775, -149.1100, -859.4896, -162.7599, -3096.4079, -1038.3529, -3896.2394, -468.6076, 1100.5865, -387.8050, 0.0000, 0.0000, 0.0000, 0.0000, -1168.5797, 39.6087, -642.4505, 53.1725, 165.0131, 400.6431, -827.4724, -1031.0323, 1606.7366, 102.2753, 670.6470, -15.7504, 714.1403, -140.9124, 1215.5364, 176.9486, 0.0000, 0.0000, -56.2227, -42.1543, -2234.8714, 1373.0765, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 146.2631, 400.5240, -69.8254, 3.5282, -410.0117, -17.9900, 0.0000, 0.0000, 0.0000, 0.0000, -173.7888, 32.8792, -225.7750, -28.3935, -150.5700, 12.1871, -444.9582, -32.2397, 0.0000, 0.0000, -1295.0353, 1.3742, -58.9182, -29.9114, -463.9804, -68.8990, 1082.0153, -1679.4891, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -3384.7610, -325.6024, 1480.4800, -1521.2825, -537.1478, 1147.4886, -1914.4855, 45.6734, 1846.2150, 722.1682, -1736.7822, 1181.1416, 0.0000, 0.0000, 0.0000, 0.0000, -1217.2553, -192.8466, -1245.9838, -52.9125, 0.0000, 0.0000, -1197.3923, 6.7553, -690.9306, -1335.0005, 1345.7813, 95.3027, 392.6439, 270.6988, -1540.7045, -102.7120, -2236.5044, -103.2950, 546.8111, 10.8600, 571.4262, -71.0990, -47.4981, -71.6035, -117.5940, -98.2675, 23.6641, -146.5150, -141.2581, -176.6744, -568.5076, -340.2322, 756.9887, 553.7092, -1325.4963, 648.3208, -184.0191, -190.8674, -266.2438, -98.9927, 82.2247, -211.8124, -48.8198, -204.2856, -57.9444, -2.0048, -104.8295, -202.2808, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.4751, -13.6498, -248.9032, 628.4643, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -298.2567, -570.0545, 0.0000, 0.0000, -298.2567, -570.0545, 0.0000, 0.0000, -44.7353, -165.5076, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -31.4400, -11.8163, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 128.9900, 30.1587, 8.7350, 20.8315, 31.4100, 162.2088, 79.9350, 200.2310, 285.9742, 182.0418, 128.9900, 30.1587, 330.1492, 212.1024, 0.0000, 0.0000, 0.0000, 0.0000, 128.9900, 30.1587, 179.0776, 226.6366, 42.5486, -297.0864, 0.0000, 0.0000, -88.7300, -144.1759, 269.4649, 2149.1330, 0.0000, 0.0000, 0.0000, 0.0000, 151.0302, 420.8061, 729.6900, 1262.9251, 0.0000, 0.0000, 0.0000, 0.0000, 198.6587, -650.5779, -88.7260, 851.6233, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 36.0632, 150.8918, 753.4839, 788.4850, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -190.8519, 611.0243, -152.2562, -1604.8035, 0.0000, 0.0000, 0.0000, 0.0000, -219.5999, -336.8115, -348.8259, -746.6103, 0.0000, 0.0000, 82.1699, 1000.5431, 888.2810, 1783.6005, -277.7979, -1020.5720, -139.0358, 1273.9738, 0.0000, 0.0000, -183.6947, -238.5187, -11.3806, -83.6447, -11.2903, -173.6776, -183.0700, 103.9772, -1080.8069, -557.4319, 0.0000, 0.0000, -193.2069, 443.1818, 70.6291, 66.7689, 42.2733, -27.1779, -762.4294, 525.8661, 0.0000, 0.0000, 0.0000, 0.0000, -55.6935, 471.2753, -815.4582, 76.8620, -132.4437, -662.6902, -634.3791, -776.5765, -28.1650, -40.8815, 52.2900, 91.9812, 36.2373, 88.6859, 738.0010, -645.7513, 0.0000, 0.0000, -146.3204, -1430.2236, -326.1570, -2320.4891, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 3.9200, 74.3618, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -921.1169, -702.6182, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 311.2526, 494.4459, 38.8927, -108.3851, 0.0000, 0.0000, -20.7050, 873.9697, 132.4421, -466.1182, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -184.3205, 204.1305, 98.9542, 675.8630, 0.0000, 0.0000, -266.3033, -516.4640, -304.6973, -660.7579, 209.5899, 1323.5714, 314.3537, 892.2011, 0.0650, 0.2143, 550.9909, 2045.3718, -3.6400, -3.5865, 0.0000, 0.0000, 940.2963, 55.5176, 55.7794, 55.7794, 55.2669, 55.2956, 0.5125, -54.2064, -136.9299, 279.2178, -67.1271, 237.4819, -69.8028, -878.4961, -1725.0481, 2831.8091, -2862.9501, 2473.3998, 1137.9020, -717.5691, 26.4877, -9.1245, 82.6212, -6.1877, 31.9174, -2.9368, -193.7934, -152.7893, -8.2348, 159.6801, -284.6336, 507.3357, -1357.0370, -70.8321, 342.1754, -403.7928, -15.2192, 4.5348, 180.6461, -27.4264, 178.9461, -25.4645, -2126.9684, -198.3957, 618.3517, 34.7859, -976.2359, -1296.5778, -657.5768, -414.5568, -1408.7927, -986.9702, 1421.8300, 99.5461, -46.5888, -75.8414, -207.1735, -1644.5195, -486.3724, 479.3461, -1942.6625, -421.4908, -757.9384, -345.7735, 137.7981, 101.5748, 1363.3390, -299.8282, -281.8968, -15.3753, 2301.0903, -383.0447, 8287.6691, 4941.4935, 209.9358, -105.9006, -89.1001, -20.1433, 57.3859, 28.0639, -4.6510, 202.1923, -39.1449, -128.0615, 222.6671, 398.6400, -1699.5591, 816.2535, 240.3616, 589.0450, -421.2736, 871.5537, -2276.5969, -65.9178, -2017.1731, -1022.1922, -544.1264, 220.8470, -661.7115, -176.0976, 64.7662, 294.5173, -278.2406, -304.4497, -433.3503, -122.3600, -321.2969, -480.6875, 98.2650, -193.3076, 317.0499, 1679.0464, -859.2030, 374.1427, 0.0300, 0.0005, 376.5036, 170.1870, -1180.0012, -803.7264, 0.0300, 0.0005, 0.4200, 0.0069, -648.0196, 1044.8118, 730.8760, 1018.1720, 0.0300, 0.0005, -316.6587, -30.7123, -1829.4985, 353.6202, 1002.9817, -311.7004, 0.0000, 0.0000, 0.0000, 0.0000, 0.0300, 0.0005, 0.0300, 0.0005, 0.0000, 0.0000, 0.3900, 0.0064, 1912.7641, 641.7832, -1143.5730, 1342.3044, 0.0000, 0.0000, 0.0500, 0.0008, 0.2400, 0.0039, 0.0300, 0.0005, 0.0400, 0.0007, 0.0700, 0.0012, 661.2056, -453.8326, -120.0556, 191.5988, 0.0000, 0.0000, 0.0000, 0.0000, 645.1565, 787.0486, -614.3229, 1240.2150, 0.0000, 0.0000, -215.0552, -1073.6211, -830.5558, -1068.2329, 886.7372, 115.6911, -2188.9678, -595.7672, 346.8172, 81.0571, 816.6147, -403.1528, 347.4110, 23.1686, -253.8481, -97.1177, 521.3494, 1657.2377, -3134.0797, -3071.7300, -673.6865, -39.0905, -173.1824, -892.2449, -90.2268, -866.2447, 1518.0607, 691.1775, 71.7844, -1412.0689, 0.0300, 0.0005, 174.6600, 5.0789, 1021.2380, 1127.9116, -570.0836, -477.2118, 1011.7836, 819.5934, 3073.1583, -226.7633, 68.4931, -163.6174, -1126.9089, -609.8617, 2606.7022, 3254.6428, -601.8172, 254.0502, 0.0000, 0.0000, -1014.3212, 467.3193, 4282.1728, 87.4767, 0.0000, 0.0000, 0.0000, 0.0000, 1.8300, 0.0301, 231.9871, 682.9572, -34.6250, -10.1528, -10.0500, -1.7840, 0.0000, 0.0000, 0.0000, 0.0000, -9.8550, -0.2861, -326.7023, -42.7436, -54.8700, -13.6396, -24.0600, -6.2442, 0.0000, 0.0000, -97.0451, 111.1722, -8.5150, -0.3877, -31.4500, -6.4437, -554.0383, 1422.0372, 0.3900, 0.0064, 0.0000, 0.0000, 0.0000, 0.0000, 3869.7495, 2613.0256, -3590.5865, -490.2235, -633.8800, -53.2175, 306.3770, 88.6780, -656.3341, -231.7084, -2797.1241, 72.4133, 0.0000, 0.0000, 0.0000, 0.0000, 109.7685, 248.5214, -1064.1286, 181.6832, 0.0000, 0.0000, 631.2796, 646.8212, -340.8583, -1450.0206, 961.3735, 41.9562, 1747.9600, -634.5930, 667.8369, -561.0743, 1087.9681, -264.6388, -9.5640, -102.5527, -224.1968, 138.0170, 1467.9883, 58.2335, 63.0599, 62.3917, 44.1120, 65.8424, 18.9479, 162.9022, 439.2279, 142.7525, -279.1103, 191.3433, 718.3382, -2505.3221, 322.9483, 2645.2481, 876.2483, -1651.5681, -553.3000, 701.4284, 101.5986, 46.4111, 95.3098, 69.3303, 110.4094, -22.9192, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -228.6302, 547.7000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -226.6599, -645.2688, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -31.9800, 17.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -513.7241, 57.6201, 1661.4903, -110.6263, 556.8118, 325.2847, -556.6463, 1119.8581, 796.4888, -553.0693, -642.5443, 213.0202, 75.3687, 1477.1057, -399.3886, 1506.7236, -63.1631, -265.4636, -603.2023, -663.2392, 15.3400, 1.2122, 282.1300, 128.4655, 0.0000, 0.0000, -199.7969, -407.2098, 169.5333, -179.3174, 0.0000, 0.0000, 0.0000, 0.0000, 4.9950, 32.7727, 293.1500, 172.5456, 0.0000, 0.0000, 0.0000, 0.0000, -0.8950, -20.4677, 217.7900, 210.3148, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -38.1450, -65.6369, -67.4067, -269.2674, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -95.7398, -598.4640, 85.6898, -759.9341, 0.0000, 0.0000, 0.0000, 0.0000, 124.9723, 355.5101, 167.7700, 162.1656, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -90.7027, -141.5537, 81.1800, 39.7982, 36.0300, 27.8156, 0.0000, 0.0000, 0.0000, 0.0000, -146.9374, -370.4700, 56.0101, -121.3963, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -15.4218, -31.6319, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -487.2701, -80.5688, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -81.3477, -265.7371, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2.1150, -30.9345, 1000.0008, 319.1368, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2854.8429, 12.1436, 12.1436, 12.1436, 12.1436, 12.1436, 0.0000, 217.0817, 263.6666, 272.3285, 123.6590, 567.9050, 140.0076, 607.5231, 249.3431, 784.6437, 387.6423, 1189.9328, -138.2992, 1620.3041, -70.0528, -32.0863, -44.7122, -94.2089, -49.9663, 62.1226, 9.6400, -8.1617, -790.8345, -556.2507, 191.7490, 0.2301, 85.0789, 97.5964, -115.2953, -12.9939, -34.8200, -26.1034, 536.7073, -157.8619, 617.1325, -140.6281, 485.5424, -27.1104, 304.5389, 120.2098, 1246.3828, 1648.5260, -236.3224, 36.4136, 366.8329, 36.8319, -31.7461, -1.0898, 6.4647, -39.4995, -63.7602, -29.8998, 756.5805, -13.7889, 1342.6115, -225.4852, 773.8406, -13.8453, 239.9840, -9.0215, -68.7983, 892.4735, 2355.9074, 434.5120, -331.8014, 289.0242, 155.3699, 135.1390, 120.8199, -224.4405, -358.0758, -53.9294, 133.3900, -215.8524, 3.6750, -64.9889, 1161.8468, 430.8169, 95.4098, 0.8869, 157.3771, -96.5580, 96.5648, 0.9449, 296.9777, 48.5022, 496.4294, 87.0061, 227.7902, -105.6812, 121.0182, -14.4224, 251.0546, 44.8942, 91.9850, 10.0788, 71.5098, -37.5268, 40.5863, 331.5199, -19.1202, -78.7749, 139.0550, 6.7362, 747.2586, -20.1056, 572.9718, -1655.2787, 0.0000, 0.0000, 165.8037, -222.9551, 165.1011, -1179.5736, 0.0000, 0.0000, 0.0000, 0.0000, -85.5736, -837.5068, 1622.9157, 1583.3088, 0.0000, 0.0000, -633.1481, -599.5188, -120.2641, 207.7648, -977.3532, -2218.6902, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -843.7937, -205.6619, -2486.5833, -1743.5398, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -41.8144, -329.8605, -384.9121, 248.9898, 0.0000, 0.0000, 0.0000, 0.0000, -102.5606, 257.3484, 145.0984, -22.4129, 0.0000, 0.0000, -51.3670, -70.1430, 659.0663, 622.0594, 18.4739, 489.7945, -694.9499, -666.8353, 33.1750, -15.9302, -399.4886, -128.1113, 80.0947, -50.6160, 246.7151, 527.6169, -127.3742, -17.1539, 315.8241, 522.7337, -633.1481, -599.5188, 20.5392, -325.5986, -1053.7488, -400.3796, -139.1107, 228.0498, 246.6600, 494.6285, 0.0000, 0.0000, 0.0000, 0.0000, -445.5095, 23.9543, -401.8861, 733.4286, -803.3403, -74.9543, 85.1519, -818.9810, 163.2850, -8.5327, -231.6854, -308.3932, 344.1902, -18.0202, -1922.4448, -2881.2896, 0.0000, 0.0000, 264.9816, 1133.8010, -851.7355, -1087.3918, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -973.5957, -4009.0145, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 10.2600, 0.0405, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 27.3600, 0.1080, 0.0000, 0.0000, 3.4200, 0.0135, 8618.2946, 1571.4590, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 127.1389, 484.9558, -649.6389, 679.8805, -3502.1305, -626.2678, 17.1208, 134.8621, -244.4200, -2.9319, -1.5900, -35.2801, 0.0000, 0.0000, 0.0000, 0.0000, 9.4948, -85.0789, -256.4768, -545.1236, 0.0000, 0.0000, -145.2267, 41.5655, 0.1073, -1425.2130, -62.7901, -39.1005, 181.1161, 884.0686, 25.3150, 1.9451, 32.2202, -675.2522, 44.4250, -66.5659, -74.1817, 278.5371, 250.1099, -83.8080, -90.4464, -90.0891, -71.2025, -86.7296, -19.2439, -557.9578, -560.1865, -503.9773, -564.4776, -562.6354, 4.2910, -354.3521, 2280.6105, -1058.6596, 1797.1854, -58.3651, 483.4251, -2037.2796, -2.1310, -3.8642, -5.2850, 8.7153, -4.1026, -12.5795, -150.6589, -50.8918, -1201.8612, -34.4905, -1063.0110, -230.1299, 419.8400, 240.8738, -1953.6765, -3.5313, 4335.9094, 146.3380, -1771.4264, 461.8578, -1467.9752, 478.1254, -2069.7671, 88.6978, -1261.4754, -283.4299, -837.0324, 812.6481, -813.4045, -596.7170, -14.3257, -354.3105, -4637.4548, 260.0943, 4025.4829, -4.5945, 13.6599, -282.0772, -109.6564, 33.1975, -535.5126, -207.2234, -464.8440, 8.9412, 1389.1399, 6.8436, -2312.6385, -619.3431, 3231.2910, 299.6530, -3348.3242, 613.3921, 8148.0784, 260.8165, 2301.9345, 20.6352, 830.0732, 140.2491, 2253.0422, 28.1122, -1325.1653, 24.2456, 1291.9812, -7.6574, -454.4901, -132.9155, -2369.0624, -385.2403, -1529.8816, -145.2831, -2906.4021, 747.8142, 548.4088, 63.9163, -456.0081, -352.1404, 1414.5412, -56.0130, 1652.8474, -38.3304, 1908.2155, 224.8185, 2306.5982, -102.9861, 639.9888, 81.0257, -2107.7176, -176.7107, -100.2520, -106.1096, 1049.7431, 236.9581, -486.4282, -200.4299, 0.0300, 0.0005, 334.7960, -61.4232, 686.3869, -1013.9785, 0.0300, 0.0005, 0.4200, 0.0068, -1089.0063, 347.8224, -987.6426, -84.4560, 0.0300, 0.0005, 7263.4007, -219.2878, -1456.6141, -181.2223, 386.9983, -362.8828, 0.0300, 0.0005, 0.0000, 0.0000, 0.0300, 0.0005, 0.0300, 0.0005, 0.0000, 0.0000, 0.4200, 0.0068, 3889.9783, -371.0148, -1500.4911, -119.6390, 0.0000, 0.0000, 0.0500, 0.0008, 0.2400, 0.0039, 0.0300, 0.0005, 0.0400, 0.0007, -1.2800, -0.2646, -1787.5518, 32.4612, -321.3837, -175.3106, 0.0200, 0.0003, 0.0000, 0.0000, 2551.0377, 111.5841, 1628.0700, -429.2795, 0.0000, 0.0000, -1825.7885, -271.0327, -1561.5735, -6.3490, -1457.3164, -212.6872, -1141.0203, 53.4175, 1839.8235, 63.8627, 1974.2415, -127.7070, -1600.0475, -49.1713, 1726.3977, -241.7281, -1780.7292, 106.6728, 861.9832, 11.1625, -826.7824, 748.1525, -1970.1556, 119.9449, 130.0608, -463.3791, 869.5381, -909.9429, -1470.4620, 161.2222, 0.0300, 0.0005, 174.7600, 8.9328, -563.2447, -323.9474, -169.2977, -1407.5850, -165.7829, 117.2808, 387.1172, -649.7187, 1524.2262, 9.7785, -1465.1838, -136.6262, 2008.5296, -16.3097, -514.3749, -1121.3791, 0.0000, 0.0000, -1127.2070, 285.3675, -571.9665, 119.4851, 0.0000, 0.0000, 0.0000, 0.0000, 1.4400, -0.0381, -387.7928, 731.5315, 13.1196, 25.6544, -747.3667, -25.2327, 0.0000, 0.0000, 0.0000, 0.0000, -1859.5914, -43.5396, -205.8143, -15.3849, 175.8555, -1.4882, -516.6032, -18.1108, 0.0000, 0.0000, -1401.6904, 32.9775, 60.8342, -8.9276, -312.8365, -26.7382, 972.9217, 509.2009, 0.3900, 0.0063, 0.0000, 0.0000, 0.0000, 0.0000, 2035.6097, -230.2016, -371.8565, -575.3046, -1053.5005, 2511.7258, -2026.3183, -74.8521, -1620.3289, -289.8082, -222.0943, 213.7302, 0.0000, 0.0000, 0.0000, 0.0000, 498.6713, -71.0402, -566.4999, 230.3271, 0.1800, 0.0029, -1192.3844, 35.2228, -1777.6098, -773.8079, 5166.7377, 19.7897, -602.9426, 369.5189, 3391.0936, -40.9357, -1775.6138, 206.4779, 1059.2291, -35.0070, -311.5075, 74.3108, -1184.8138, -35.8063, -87.1367, -185.4691, 195.5624, 398.3705, -282.6992, 417.4290, -146.8660, -530.0747, 987.1164, 2010.9081, -1133.9823, -491.4812, 103.1234, 88.8154, -357.0080, 619.1107, 460.1314, 347.0055, -31.9081, -68.6713, -56.7730, -0.0985, 18.9771, -68.5728, -12.7300, -12.4817, -2282.2511, 946.1164, -1191.1492, 245.6219, -1892.5414, 1549.5804, 220.3074, -84.7025, -290.1994, -373.9057, 1641.7860, -1157.4032, 1600.9911, -1068.1273, 2.9207, 347.1618, 803.3388, 2378.4917, 2014.9298, -734.2728, -4367.5317, -120.6888, 820.4639, -271.9889, -417.8126, -414.2713, 176.0181, 208.1223, -138.8361, -387.6248, 337.6856, -1436.1275, 716.6261, -3133.0185, 299.7717, -1483.3963, 31.8742, 52.7293, -903.2230, 1445.4318, 510.4010, 2337.6144, -4.2136, -1196.8447, 1145.7784, 111.8576, 738.9028, -67.4602, 355.4014, 883.8551, 809.6878, -57.5309, 269.3100, 51.5724, -578.7110, 371.3542, 446.6625, 127.5533, 620.0834, -128.0886, 762.6233, 111.7558, 3450.5498, 810.4233, 2244.6929, -1074.6804, 1504.5244, -1113.8778, -812.8814, 222.7996, 1201.2081, 852.9847, 1433.0980, 208.0525, 670.0215, 713.7828, 225.0691, -236.5621, -2904.2284, 348.9898, -477.8607, 602.7347, -1419.2140, 1567.2291, 939.7853, -2330.3506, 0.0000, 0.0000, 7952.9392, -41.8705, 102.3332, -58.5857, 0.0000, 0.0000, 0.0000, 0.0000, 1636.0349, 106.6150, -1090.4442, 62.1176, 0.0000, 0.0000, 920.6307, -105.6446, 480.5347, -24.9598, -1416.4722, 285.1651, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -388.0167, -1192.2900, -3194.6979, 1175.4602, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -8.6249, 1033.2826, -2106.1594, -690.2531, 0.0000, 0.0000, 0.0000, 0.0000, 2743.0223, 362.5663, 2169.5806, 1402.4247, 0.0000, 0.0000, 436.8489, -438.1009, -2770.5898, -228.9163, 819.2596, 412.0202, 1289.3894, -514.5524, -369.7164, 34.6545, -1585.0496, -413.3994, -1427.8323, -5.0367, -863.3615, 505.5984, -3117.3183, 1341.4147, -185.1601, -100.5400, 889.1057, -131.9629, 658.9808, 236.2549, -2725.8415, -17.7700, -1448.0906, -973.7849, 1478.5301, -126.5503, 0.0000, 0.0000, 0.0000, 0.0000, -1894.4165, -894.3603, -5656.6051, -998.0995, -2295.5496, 364.6393, 404.4890, -991.9571, 3559.0202, 434.6163, -716.7447, -93.1910, 1669.6116, 3040.8616, 970.6157, -1789.6774, 0.0000, 0.0000, 3033.2505, 158.3549, -758.6204, 68.6420, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 807.0430, -1946.5835, -4.5550, -2.2328, 18.0750, 2.3193, 0.0000, 0.0000, 0.0000, 0.0000, -4.5550, -2.2328, -7.4650, 117.0234, -24.0200, -39.8548, -4.5550, -2.2328, 0.0000, 0.0000, -12.2300, -2.0772, -2.1350, 2.8359, 40.8900, -25.3195, 2954.9958, -821.5614, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 663.5619, -1407.5843, 646.0198, -3093.2789, -330.1644, -77.3179, 302.8481, 1533.2663, -3214.6947, -784.4490, -211.4500, 194.9697, 0.0000, 0.0000, 0.0000, 0.0000, -1272.5034, 140.1648, 966.7414, 630.2165, 0.0000, 0.0000, -1210.9894, -331.4182, 118.6507, 128.2789, -530.7965, -211.7970, -2582.0155, 780.4464, 435.5641, 72.1218, 1899.7303, -673.7889, 570.0401, -20.7311, -2677.7031, 138.6767, -881.9357, -34.7327, -39.6048, -26.9789, -19.4851, -29.3186, -20.1197, -253.0030, -672.6792, -234.6377, 58.7588, -103.3563, -731.4379, 1701.7022, -319.9649, -62.5049, -106.8838, -48.7223, -213.0811, -124.6727, 23.8980, 84.9870, 45.7929, 38.3897, -75.3050, 46.5972, -2.0100, -0.0786, 3029.8060, 2052.8291, 36.1857, 41.6533, -1367.5203, -55.7277, 2.3400, -0.0569, 0.0000, 0.0000, -345.0546, -212.3367, -345.0946, -201.8255, 2.6550, 1.0202, 192.2999, 131.6330, -966.3498, -176.9989, -2.5800, 0.6242, -45.9250, -8.7839, -28.1400, -1.1001, 0.0300, 0.0167, -12.1250, -1.5839, -88.3399, -71.0092, 0.5500, 0.0576, -88.3499, -71.0152, 0.0000, 0.0000, -3960.0944, -974.8117, 1071.7094, 844.8993, 341.8231, 75.6079, 4406.8971, 1857.9255, 288.3599, 224.0766, 0.3450, 0.2319, 287.3549, 224.0374, 0.0100, 0.0060, 267.6100, 110.6661, 0.0000, 0.0000, -35.5550, -2.4903, -2.0100, -0.0786, -611.9001, -11.1867, -231.2456, -316.0203, -478.4321, -350.3493, 105.3223, 30.9927, 447.8443, 131.3967, -212.5091, -51.5616, 409.8732, 11.9840, 17.6000, 1.5279, -96.3601, -155.2909, -2.8050, -0.1532, 1973.4354, 375.8269, -3028.2550, -1794.5341, 0.0000, 0.0000, 2100.6521, 145.8366, 956.4424, -379.9706, 0.0000, 0.0000, 0.0000, 0.0000, 763.5054, 1411.3202, -2231.1300, 1483.1135, 0.0000, 0.0000, -110.7300, -6.5764, 3521.4536, -456.7151, -2510.7779, -1579.9264, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 5110.0259, 1358.6907, -3188.6502, 1424.4441, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -303.7828, -526.4011, 815.5879, 18.4006, 0.0000, 0.0000, 0.0000, 0.0000, -1448.5503, -0.7512, 2528.6222, -1355.8146, 0.0000, 0.0000, 371.6131, -205.1517, 1342.2274, 1832.7851, 851.1961, -30.9681, 1276.7402, -1287.9492, 74.3155, 98.6213, 516.5918, 567.6616, -893.5172, 5.8483, 363.1259, -503.3419, -436.0307, 256.6936, 8.2605, -406.3691, -110.7300, -6.5764, 2163.3208, -247.6707, -622.6591, 160.8730, 1186.8949, -1044.3309, -942.7284, 640.3900, 0.0000, 0.0000, 0.0000, 0.0000, 2407.9206, 770.3533, -3078.9259, -1250.0114, -688.7409, -1499.1223, -2615.2199, 813.0350, -246.1141, -74.6555, 228.3402, -96.6811, 3041.6186, -67.6967, -1939.4765, 338.1156, 0.0000, 0.0000, 3122.3201, -307.5190, 1218.4663, 566.4663, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -912.7340, 6.1013, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 85.4800, 70.0656, 2613.5775, 3850.8766, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 3856.7635, -408.0128, -3941.3220, -930.9982, -25.3500, -3.8006, -637.5879, 548.4686, -3204.2882, -127.2516, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1564.7192, -180.8937, -852.3548, 693.5415, 0.0000, 0.0000, -641.0864, 169.1928, -2131.6996, -1157.8873, 1017.9592, -110.7643, -350.4730, 890.2543, 956.6029, 49.5266, -3016.1680, 173.3532, -29.3567, -110.4074, -977.0355, -297.9997, -1489.6829, 14.7908, 15.8270, 15.8620, 16.3677, 15.8720, -0.5408, 66.3977, 116.2274, 134.8682, -12.2366, -522.3588, 128.4640, -477.7694, -1079.1129, 1243.3772, -1150.9008, -2047.6511, 71.7879, 1165.5038, -19.7273, -185.2419, 69.4012, -49.1689, -21.7464, -136.0730, 509.6069, -175.0864, 550.4053, -1302.4055, 1317.4715, -2610.1766, -765.4916, -1034.6702, 476.1460, 344.8714, 2116.1078, -61.8772, -1458.6325, 377.1828, -1670.8674, 352.8991, -314.0780, 298.9458, -2045.9612, -288.2741, -29.1319, 700.2723, -517.7252, 149.9475, 1988.7281, -63.8169, -5914.5818, 19.5616, 3029.9289, 519.6100, -538.7286, -268.9803, -284.2441, -450.6357, 623.0246, 1367.8583, -285.5736, -481.3861, 847.7766, -213.6053, -2614.0951, -1015.3464, 740.2783, -390.8495, 55.3549, 793.7476, -4786.0274, -347.3334, 1840.9761, 2071.6167, 853.6584, 1485.2168, 1860.2962, 1930.9656, -274.0900, -112.7712, 2102.3603, 47.8672, -965.2988, -352.9036, -371.9961, -524.9478, -1247.9310, -667.2440, -1249.2911, -661.0694, 2730.4394, -1005.0789, 1782.5513, 890.2840, 1416.7350, 1561.0884, 1919.4107, 82.0549, 1667.8573, 114.3909, 2346.6637, 153.1168, 2217.9682, 10.8992, -2977.1066, 136.6309, 117.4340, -85.8095, -627.0030, 1651.3839, 28.3608, 270.2561, 0.0000, 0.0000, 2548.6499, 211.4165, 3119.7803, 43.7821, 0.0000, 0.0000, 0.0000, 0.0000, -1893.1722, 98.8074, -3345.8861, 860.2553, 0.0000, 0.0000, 8445.9709, -1033.3582, -4142.4703, -850.8658, -2841.9477, -1309.1304, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2194.8967, 10.6369, -67.4699, -220.7054, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1364.4700, 987.1096, -227.6424, 1514.9112, 0.0000, 0.0000, 0.0000, 0.0000, 1834.3379, 543.5256, -313.9952, -873.4663, 0.0000, 0.0000, -3011.4213, -426.8292, -4245.8071, 469.6256, -1036.4195, 4.9948, -2306.1998, 1352.1740, 1317.5917, 200.6349, 3451.5240, 487.8881, 728.0666, 1104.9248, 2726.7297, 475.0508, -3195.7989, -643.0316, -60.1663, 878.6865, 0.0000, 0.0000, -1695.5024, -581.0012, 510.4666, -395.5370, 3078.8133, -1379.8548, -653.0647, 1070.9016, 0.0000, 0.0000, 0.0000, 0.0000, -2142.6259, -1293.4680, -609.6834, -959.9006, 4936.1447, 2592.8960, -629.6467, -1285.3950, 2807.5364, 538.4943, 1899.9939, -117.4411, -3323.4815, -657.6375, -3138.3257, -478.4557, 0.0000, 0.0000, -1557.5860, 104.9864, -1634.2856, 2711.9606, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -664.5762, -810.4059, 22.3400, 81.1247, -40.8550, -35.7391, 0.0000, 0.0000, 0.0000, 0.0000, -1418.4526, -33.0195, -49.8500, -1.2142, -54.0150, -1.8884, -11.3400, -10.2188, 0.0000, 0.0000, -40.4201, 217.2671, 2.5300, -1.3303, -23.4785, -63.4551, 200.3594, 111.6198, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1033.8159, -354.4114, 4319.6196, -1554.9049, 2481.2395, -2051.2995, -417.5489, -139.3652, -2875.0727, 269.4442, -1459.7357, 895.1992, 0.0000, 0.0000, 0.0000, 0.0000, 243.6192, -407.7738, -1204.2371, 984.9758, 0.0000, 0.0000, -565.4512, 471.7997, 548.5010, -32.3116, 992.7147, -171.2910, 1300.2335, 2108.7483, 1508.1082, -85.8194, -1185.8880, 723.1000, 2042.5895, 130.6120, -488.0617, 409.1373, -1510.8192, 67.2642, 48.1116, 51.8120, 77.5861, 32.4043, -29.4745, -665.6370, -214.7057, -742.7590, -420.1662, -794.9764, 205.4605, 441.9635, -258.5257, -357.9507, -280.0820, 22.4255, 21.5564, 632.9622, -75.4042, -58.1195, -170.6582, 27.4062, -210.2371, -85.5257, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -43.6549, -39.0508, 1342.4025, 776.6035, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -680.8739, 85.5119, 0.0000, 0.0000, -680.8739, 85.5119, 0.0000, 0.0000, -83.2603, -232.9528, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -37.1850, -11.7821, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 158.1500, -15.9654, 130.6127, 88.6498, -5.9618, -96.1955, 113.9082, -46.4477, 167.5488, -552.8614, 161.2100, -4.4166, 376.5265, -450.0839, 0.0000, 0.0000, 0.0000, 0.0000, 150.2050, -9.8647, -84.2978, 634.3769, 519.7594, -1279.5233, 0.0000, 0.0000, -190.7152, -114.5398, -2931.8986, 1940.0403, 0.0000, 0.0000, 0.0000, 0.0000, 519.0643, 653.2185, -3132.3313, -931.3350, 0.0000, 0.0000, 0.0000, 0.0000, 122.7026, 63.8387, 307.9916, -13.5647, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -118.4522, 274.6017, 272.6955, 3520.9009, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -305.5032, 133.1095, 120.4438, 528.4300, 0.0000, 0.0000, 0.0000, 0.0000, -273.7274, -193.0689, 2075.9832, 489.2382, 0.0000, 0.0000, 114.4741, 552.8559, -42.5632, -215.8139, -179.9923, -617.0187, 1637.2517, -1764.0757, 2.6350, 0.6587, -3388.9217, -797.2020, -55.8856, -81.0455, -295.8268, -228.0129, -297.5800, -189.7189, -542.8828, -311.0038, 0.0000, 0.0000, 69.5209, 64.5883, 2144.6127, -30.5112, -183.0506, -36.7257, 2090.5933, 1133.4123, 0.0000, 0.0000, 0.0000, 0.0000, -3339.3225, -545.1632, 411.0529, 312.6678, -2840.5213, -267.1398, -1192.8829, -35.2836, -31.5550, -26.6158, 203.4651, 43.6993, -275.7928, 272.0839, 3197.3636, -513.1085, 0.0000, 0.0000, 737.7943, 2208.7799, 2088.4084, -1778.9323, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 6.6750, 75.9798, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -183.4455, 663.8417, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 88.0075, -46.7138, 294.1616, 445.3271, 0.0000, 0.0000, 74.9100, -269.0123, 499.2550, 509.7861, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -383.7805, 217.7267, 288.1705, -934.7224, 0.0000, 0.0000, -550.9853, -473.1375, -627.4805, -1935.0980, 298.9549, 379.4490, 173.3398, 1020.8663, -48.7547, -13.7754, 2080.6301, 2353.6282, -1.9350, -1.8135, 29.0300, 23.3990, 204.5340, 37.1174, 37.3895, 37.3895, 36.8361, 36.9057, 0.5534, 24.5987, 220.2631, 11.7831, 115.8278, 15.4028, 104.4353, 471.2825, -825.1691, -623.3404, 909.6389, -287.5504, -1734.8080, 221.0615, 49.6619, 11.0208, 94.0818, 1.6906, 36.6815, 9.3302, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2.1700, -1.9727, -2.1700, -1.9727, 0.0000, 0.0000, 83.5300, 28.6300, -912.3590, -44.2924, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -34.5250, 1195.8650, 0.0000, 0.0000, -86.6350, -49.7742, 0.0000, 0.0000, 117.5900, 20.6464, 0.0000, 0.0000, 0.0000, 0.0000, -7.5402, -23.0830, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -158.4194, -80.3743, 0.0000, 0.0000, -1.7500, -0.6228, 0.0000, 0.0000, 346.5100, 95.0405, -69.6198, -83.7998, -410.6495, -312.2789, -363.7948, -224.2782, -190.9250, -144.8059, 340.1254, 139.0783, -73.0350, -135.4928, 0.0000, 0.0000, -11.7550, -20.5557, 354.6450, 99.7769, -613.7483, 1216.6890, 619.6031, 1601.9155, 0.0000, 0.0000, -444.8018, -480.5547, -70.2090, 929.8863, 0.0000, 0.0000, 0.0000, 0.0000, 860.2236, 209.7804, 875.6562, 1060.5874, 0.0000, 0.0000, 0.0000, 0.0000, -687.6758, -700.4466, -1405.4200, -1196.9575, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -248.7375, 1349.1993, 719.0487, 630.0131, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1050.0610, -183.4597, 220.0671, 1031.4111, 0.0000, 0.0000, 0.0000, 0.0000, 397.8130, 253.1674, 895.8010, -267.6762, 0.0000, 0.0000, 200.6156, 863.8962, 1657.6346, 1614.3872, -79.5185, -305.5686, 835.4881, 1272.2600, 29.3800, 13.9355, -208.2702, 137.3781, -265.8027, 122.6249, -498.1686, -449.7217, -646.6081, 263.6180, 1027.0140, 2158.4195, 0.0000, 0.0000, -1927.8795, -2136.2077, -333.8494, 750.8744, -208.3509, -1299.0869, 764.2971, 336.0266, 0.0000, 0.0000, 0.0000, 0.0000, -125.8197, 260.1676, -1637.6110, 1841.6719, -756.5052, 640.5483, 372.4468, 87.7915, 108.3050, -19.5122, -269.7977, -173.9244, 707.6293, 236.3602, 566.5744, 693.8279, 0.0000, 0.0000, -607.6277, -380.9234, 406.7558, 1244.1649, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -10.9850, -5.4191, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1004.4485, 1043.0493, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 77.7902, -1739.6686, 2888.4349, 501.7300, 0.0000, 0.0000, -349.9173, -0.3706, 1134.3842, 195.8428, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -41.7999, 439.8708, 381.5411, 309.6524, 0.0000, 0.0000, -1974.2249, -513.2330, -858.7753, -332.7814, 355.6600, -307.1476, -799.1282, 250.4927, -20.5100, 74.9220, 631.9659, 399.3799, 27.5700, 36.3670, -0.4798, -33.6053, 1739.3837, 129.6032, 129.5833, 129.5833, 129.7352, 129.5833, -0.1519, 233.3590, 364.5693, 464.8435, 99.2978, 357.6070, 265.2714, -980.9640, 928.3047, -913.7318, -722.6964, 529.2238, 1651.0011, -463.5304, -42.5023, -19.8765, -42.6802, -33.4940, -28.1589, 13.6174, -3.3650, -90.6250, 0.0000, 0.0000, 122.7337, -229.1992, 27.3500, 911.6667, -26.5300, 79.6063, -14.9035, 444.2444, -202.2959, 1618.1159, 68.1203, 330.1691, 3.5350, 758.3750, -113.5457, -1422.3810, 409.5191, 1120.4145, -666.1897, -641.8451, 0.0000, 0.0000, 2.6850, 0.0026, -11.6300, -0.9500, 22.8100, 0.0220, 6.1950, 9.5217, 13.6900, 0.0132, 0.0000, 0.0000, -111.1890, -126.6853, -105.4940, -124.7815, 41.7650, 0.0403, -14.1050, -3.3339, -29.4350, 3.4014, 1185.6462, 446.6777, -764.0799, -272.3671, 0.0000, 0.0000, -275.9573, -118.9336, 0.0000, 0.0000, -21.9650, -2.9946, 1065.0234, 424.7249, -12.3890, -0.0332, 0.0000, 0.0000, -550.2244, -1974.7549, -31.7950, -5.1082, -183.8000, -9.9096, 3507.0074, 1050.6914, -198.8563, 1203.3095, 0.0000, 0.0000, -199.0513, 1203.1145, 6.3650, 0.0061, 17.8450, 0.0172, 0.0000, 0.0000, 813.9940, 260.2242, 0.0000, 0.0000, 2209.4361, 957.3015, 2946.5659, 1114.1761, -216.5115, 536.6805, 804.0232, 327.2472, -99.8160, -20.6131, 673.3715, 137.1603, -119.6180, -146.1821, -253.3350, 433.3296, -179.3300, -272.8786, 51.8550, 46.2491, 318.8026, -3.6538, 480.6504, 554.4751, 0.0000, 0.0000, -3707.6794, 62.4727, -3754.6210, -1988.8505, 0.0000, 0.0000, 0.0000, 0.0000, -1825.8094, 1320.2955, 2903.2347, 1567.0952, 0.0000, 0.0000, -35.3450, -2.7426, -317.9330, 246.5519, 888.0611, -1368.2596, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -5753.3700, -877.3186, 1203.3717, 759.0884, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -3753.8459, 333.3982, 1127.6933, 113.6694, 0.0000, 0.0000, 0.0000, 0.0000, -77.3448, -74.3710, -2832.8472, -1027.0313, 0.0000, 0.0000, 858.9504, -487.1622, 570.3418, -89.0570, 2864.1621, -585.7555, 539.6199, 390.9464, -934.2305, -142.1905, -1453.2074, -178.6208, -634.3785, -52.0968, -3898.7466, -259.6919, 434.2964, 1076.0484, 339.0307, -314.7481, -35.5400, -2.9376, 883.3587, 1197.0703, -144.5462, -589.0357, 2430.4968, -1686.8520, 2174.5381, -275.4826, 0.0000, 0.0000, 0.0000, 0.0000, -1563.3319, 186.1463, 3462.7682, -2285.6026, 704.8145, -81.2871, -400.0573, -112.5477, -2494.0197, -53.7453, -2642.9482, -382.9180, -3996.6200, 1100.0791, 198.0042, 381.4283, 0.0000, 0.0000, 1228.1412, 1953.2466, -1033.7896, 257.4504, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -153.6400, -24.0862, -1.2850, -0.2388, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1.2850, -0.2388, 0.0000, 0.0000, 0.0000, 0.0000, -1.2850, -0.2388, 0.0000, 0.0000, -5.7850, -1.5011, -1.2850, -0.2388, -1.2850, -0.2388, 4070.2948, 1944.3731, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -6397.6441, 1227.7876, 884.7621, -523.8159, -63.7600, -3.4280, 912.4646, 992.7425, 2357.6227, -643.7623, -55.2050, -12.1038, 0.0000, 0.0000, 0.0000, 0.0000, 973.3856, -185.3108, 2376.4421, -1660.5230, 0.0000, 0.0000, 1655.0059, 149.4107, 2644.1911, -1388.4489, 856.8250, 177.0763, -1429.3773, -963.0957, -790.7626, 96.5088, 3208.4303, 1339.5104, -1423.9312, -98.4153, 1731.8550, 326.7134, -823.4005, 24.6091, 24.5595, 24.5595, 25.7350, 24.5595, -1.1755, -259.7249, 17.3797, -353.0965, 753.8732, -927.1369, -736.4935, -249.7320, 146.9908, -444.9803, 1704.1946, 473.4508, -1557.2038, -415.7244, 66.5929, 1.6601, 62.6669, 48.5516, -1.0702, -46.8915)
    
    # 权重2，由网络采集的样本得到
    # Weighted feature vector generated from ModelTrainer.cs/ModelTrainer.exe during the training phase based on in-the-wild samples.
    <#
        Accuracy: 0.9605
        Precision: 0.9609
        Recall: 0.9353
        F1Score: 0.9479
        TruePositiveRate: 0.3595
        FalsePositiveRate: 0.0146
        TrueNegativeRate: 0.6010
        FalseNegativeRate: 0.0249
    #>
    [System.Double[]] $highConfidenceWeightedVector = @(-218.9926, -4217.0000, 4076.5585, -350918.0000, 77447.5892, -3002.5000, -22984.7197, -23885.5079, 26376.7328, 1352.0000, -608.9274, -12721.5000, -3720.4697, 54935.0000, 15304.8156, 56435.5000, 11551.4227, 32070.0000, -27850.5045, 363390.4960, 48386.7596, 86796.4960, 115933.7263, -142831.0000, -19778.0061, 27639.5000, -16901.6964, -112857.0000, -18112.9123, 36851.0000, 26375.9568, -42031.5000, -12559.1599, 68426.5000, -18339.7905, 11003.5000, -53896.8043, 67648.0000, -17532.5011, 23215.5000, 36132.7856, -69678.5000, -25248.0458, 38203.5000, 11361.4763, -240334.0000, -38771.9378, 49142.5000, 64353.4157, 10302.4960, 406.4446, -34459.5000, -2955.8546, 21300.9960, 2941.5979, 5791.0000, 1330.2587, 36602.0000, 2619.8913, 12664.5000, 4416.3735, -100050.0000, -37366.5084, 5710.0000, 2633.9551, 158147.9603, -18158.4740, 161825.9722, -20001.9312, 64935.0000, -43777.5056, 31906.5000, 13462.1346, 60106.5000, 7133.7619, 40188.5000, -14606.4479, 54331.5000, -29268.7191, 149030.5000, 26262.2372, 8987.5000, 15514.3012, 86613.5000, 37693.3862, 187087.5000, 2204.9358, 27173.9960, 486.4059, 0.0000, 0.0000, -8004.5000, -217.8750, -55554.5000, -31207.3051, 0.0000, 0.0000, 0.0000, 0.0000, -72100.5000, 86486.3632, -88222.0000, 41537.6909, 0.0000, 0.0000, -2667.5000, -27812.5092, -107955.0000, -8038.1221, 23575.0000, -3766.3804, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 13134.5000, 59394.3285, -351454.5079, -45218.3629, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -42456.5000, -29448.2914, -137057.0000, -36669.7391, 0.0000, 0.0000, 0.0000, 0.0000, 29407.5000, -7420.5964, 70425.0000, -8844.7808, 0.0000, 0.0000, -48852.0000, 21308.9596, -1675.0000, -1933.1864, 48472.0000, -28527.1497, -97878.0040, -47333.7029, 3547.0000, 522.4471, 10310.5000, -8538.2819, 15427.0000, -4334.7155, -6519.0000, -17989.5282, -32726.0000, 28561.3750, 4784.0000, 80642.3300, -12982.0000, -31347.0188, 1614.0000, -12886.6517, -112068.5040, 57295.8071, 33703.9960, 11522.2887, 81468.4960, -33591.6668, 0.0000, 0.0000, 0.0000, 0.0000, -27937.0000, 26070.8949, -103030.5079, -4833.0293, -1363.0000, -2307.2810, 20645.4960, -14011.9169, 27957.5000, 320.5283, -18510.5000, 795.1956, 77451.0000, 37640.6490, -61290.0040, -72043.3138, 0.0000, 0.0000, -49760.0000, 55665.9162, 2852.4921, 102162.5496, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -46392.0040, -342894.6217, -27.0000, -10.1504, -189.5000, -87.7857, 0.0000, 0.0000, 0.0000, 0.0000, -141.0000, -31.6844, -2200.0000, -1916.4295, -2379.0000, -2571.2031, -33.5000, -22.9452, 0.0000, 0.0000, -163.5000, -73.6171, -5.0000, 2.2063, -58.0000, -0.4324, -131203.0238, 98853.8327, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -56215.5000, 6745.3940, 39612.4960, 29438.4945, -34547.0000, -13407.8070, 26097.5000, -10706.2602, 24924.4960, -79049.6027, 4166.5000, -3643.5382, 0.0000, 0.0000, 0.0000, 0.0000, 20618.5000, -35446.3171, -86654.5000, -16795.3228, 0.0000, 0.0000, 39911.5000, 126.9759, -21680.5000, 5683.3709, 983.5000, 26975.6571, 10814.5000, -3229.7618, 45526.5000, 32373.3740, 59797.0000, 86263.8974, 33857.0000, 2774.9499, 2687.5000, 1330.8370, 66643.9960, 2194.0103, 671.8628, 1746.9361, 2862.1353, 1826.1303, -2190.2725, -12279.1737, -14757.0354, -23920.2607, -4915.7266, -1697.7842, -9841.3088, 202986.8057, 7160.8451, -65918.6549, -40506.1549, -7782.1549, 47667.0000, -14147.6549, 5549.2654, 7313.9062, 3637.4878, 6103.5188, 2562.6387, 1210.3874, 82190.9960, -8968.6441, -5088.5000, -103464.3136, -8930.5000, 123928.6540, -903.0000, -26553.2834, 114.5000, -11250.2404, -633.5000, -15657.6612, -205.0000, -26939.4509, 16.0000, 767.1429, 1.0000, 38.6667, 29.5000, 2814.2857, 52.5000, -9315.5530, -107.0000, -336.5613, 41813.0174, 44708.2506, -6201.5000, 13943.9674, -430.5000, -5534.8641, -12809.0000, -85542.9416, -50.0000, -238.0952, 0.0000, 0.0000, 37809.5000, 7948.6253, 66643.9960, -43671.7999, 22215.0174, 59074.8887, 0.0000, 0.0000, 0.0000, 0.0000, 188394.4921, 49708.8084, 0.0000, 0.0000, -861.0000, -489.2960, 0.0000, 0.0000, 503734.5066, 7694.2607, 8.0000, 5.3333, -29374.0000, -7279.6824, -45533.0000, -9120.3508, 52239.4588, -51351.9333, 0.0000, 0.0000, 0.0000, 0.0000, -229617.4967, 35684.7944, -72045.0324, -33307.4715, 0.0000, 0.0000, -512.5000, -2993.8166, -235442.5104, -23011.2153, -10267.5000, -11294.7120, -43369.4961, 18359.2780, 1646.5000, 465.0286, 5665.0000, -1793.3380, 1823.5000, -253.1404, 3609.0000, -7437.5298, -48817.5000, -19976.1483, -50829.5000, -17631.2774, -37489.5000, -8945.3823, 136557.5091, -19439.1383, 0.0000, 0.0000, 14549.5000, 6424.2292, 1234.5000, -21033.8734, -8884.0000, 2883.9946, 141138.0005, 35698.7422, 27137.0000, 6498.5165, 41603.5039, -28973.9256, -90224.9984, -30343.5144, -69428.5000, 18854.5635, -178442.4988, 719.7524, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -19022.0326, 339682.9148, 1008.0000, 492.9424, -5696.0040, 15692.1185, -59922.2688, 26109.2759, 44230.4964, 13824.9336, 39273.4968, -38112.6181, 162393.4981, 188644.2534, -5020.0313, -66122.8954, 0.0000, 0.0000, 51444.5000, 17580.0844, 0.0000, 0.0000, -35325.5040, 15382.3826, -5541.2609, 34412.0748, -147627.0090, -42099.6217, 0.0000, 0.0000, 0.0000, 0.0000, -164610.4984, -55498.8924, -384713.5666, -17331.0358, 158672.0000, 31278.3195, -17229.0000, -7847.8578, -32420.0000, -8638.7993, 6359.0000, 3770.1574, -36988.0000, -11063.6639, -53220.5000, 5550.4490, 10157.0000, 2314.6943, 41442.4915, -56971.5828, -149545.9980, -23737.2204, 0.0000, 0.0000, -127.5000, -254.7540, 1.0000, 1.2500, 983.0027, -201889.1027, 9816.5000, 17933.6860, -6643.0000, -78056.9415, -15346.0000, -185784.7864, -7852.0000, -71891.4698, 7400.5000, -72026.7151, -1399.0000, -15726.2163, 0.0000, 0.0000, 741.5000, 22249.9594, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 120.5000, 8825.0000, 0.0000, 0.0000, 2943.0000, 4400.8040, -658.0000, -3913.4191, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 442.0000, 295.9936, 6023.5000, 16542.0177, 0.0000, 0.0000, -13830.0000, 49388.8319, -38612.5000, -169493.9107, 107842.5000, 38212.6137, -4651.5000, 7987.8186, 10482.4971, -5134.7769, -8629.5000, 97987.3390, 8396.0000, -86860.9262, -1396.0000, -1177.7675, -4397.0000, 80020.3827, -44792.5000, 50424.2713, -37972.5000, -83002.0634, 25592.5000, 47183.7918, 37484.5004, 35828.4140, 13714.5000, -41067.5400, -1174.5000, -4621.8717, 1358.0000, -3824.5578, 13909.0000, -30059.2334, 4119.5000, -206541.3146, -22404.0000, -248169.0645, -9096.5000, -156959.2388, 16960.0000, 114072.4059, 27428.0000, 141148.9742, -80322.5000, -8875.7352, -57731.0000, -187172.1326, 8355.0000, -33260.7589, 574693.0091, 34174.2647, -5747.0000, 47249.9735, 31.5000, 64.6127, 85.0000, 125.0000, -1754.0000, -12322.1245, 21.0000, 10.2439, -3138.5000, -198.7675, -21964.5000, -5011.8652, -4602.0000, -2866.7171, -17270.5000, 21653.0595, -39377.5160, 18118.8755, 8363.0004, -202771.0862, -2537.0000, -320.3458, -2904.0000, -424.0460, -2776.5000, -3432.9937, -3601.5000, -327.1050, -89464.9996, -15010.0004, 43651.0000, 13923.3471, 176098.5000, 15354.1726, -1632.0000, -103.7618, 15764.4984, -12754.6260, -8127.5000, 101401.8747, -19870.0000, -4407.9192, -26987.5000, -22516.8122, -18753.0000, 6777.4776, -13.5000, -7.2193, 125555.5000, 32368.4850, -13012.5000, -3663.9897, -230711.5171, -25277.7594, 548842.5000, 284902.0829, -6453.0000, -2985.7124, -576.0000, -117.1755, -6431.0000, -2996.2890, -118.5000, -73.8828, -45540.0000, -6373.8673, -153687.5000, -23915.8132, 1492.5000, 4546.2503, -5717.5000, -39161.3268, -117451.0000, -561.3454, -18474.0000, -2191.8046, -17529.0000, -4771.7738, -28524.5000, -7733.0232, -49564.0000, -2121.4370, -51435.4992, 6818.4114, -48880.0000, -628.1581, -50747.0000, -1402.8815, -44169.0000, -648.9401, -46776.5000, -453.6758, -133693.5000, -20354.4592, -110006.4988, 25759.7033, 0.0000, 0.0000, -64179.0000, 34949.7360, 200911.9795, 88323.7974, 0.0000, 0.0000, 0.0000, 0.0000, -73076.0040, -17445.4047, -76322.5151, -50983.9260, 0.0000, 0.0000, -12731.5000, -2096.1225, -171646.5071, 53958.3341, -52018.4961, -120062.4226, 1831.5000, 9639.4737, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1831.5000, 9639.4737, 55222.5000, 16670.5238, 204543.9368, 75883.9633, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -113950.0000, -41752.5072, -121202.4999, 47437.3867, 0.0000, 0.0000, 0.0000, 0.0000, -49778.5078, 53871.0559, 107623.4894, -108713.0842, 0.0000, 0.0000, -101901.4988, -52322.0672, 177350.0051, 5145.3998, 165262.0039, 26093.6394, -92724.5093, -97773.3014, 48442.5000, 32390.1340, -95747.5040, -7893.8505, 5200.0000, 4986.9400, 31273.5039, -23860.0069, -147706.0000, -14914.3940, 72208.4915, 132803.3074, -12999.0000, -2123.3276, 67316.4962, 92896.3010, 231363.9914, 36137.9705, 38848.9960, 40961.1102, 72588.9963, -185652.6378, 0.0000, 0.0000, -1941.0000, -240629.8538, -72944.5040, -15062.5849, -35801.4986, -72384.3526, 119506.5012, -68347.8922, 13891.5001, -4229.0073, -188886.5000, -18240.7468, -18945.5000, -9757.3795, 96550.0039, -23240.9283, -83233.5272, -35970.7262, 0.0000, 0.0000, 7324.4921, 23325.2308, 167336.4979, -61315.0215, 0.0000, 0.0000, 0.0000, 0.0000, -8.5000, -12.3188, -50988.5000, -6420.7954, -271.5000, -90.2700, -72.0000, -14.1896, 0.0000, 0.0000, 0.0000, 0.0000, -133.0000, -43.3247, -250.5000, -90.6177, -476.5000, -206.8010, -128.5000, -46.3626, 0.0000, 0.0000, -2101.5000, -1506.2802, -9.5000, -11.0465, -201.0000, -54.3353, 167117.9661, -56843.3717, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 213207.9973, 12626.8609, -51791.5229, -136642.0849, -3991.0000, -719.7766, -28977.0000, 3877.3964, -68222.0117, -104157.1725, -12719.5000, 44352.6597, 0.0000, 0.0000, 0.0000, 0.0000, 268990.0000, 69969.2195, 145410.5000, -55642.9431, 0.0000, 0.0000, -76883.0067, -54230.2973, 69947.4961, 83079.8315, 44797.5000, 9072.6208, -68566.0000, -2162.6419, -6201.0000, 9121.0343, -84569.5000, -66842.4105, 473.5000, -2278.9042, -12855.5000, -25906.6861, 52239.4588, -5958.3521, -5985.2167, -5985.2167, -5812.7022, -5985.2167, -172.5145, -12861.5314, -7432.9263, -12944.0441, -23976.1418, 16245.6557, 16543.2155, -4871.7088, -84420.0443, 33009.0221, 33476.5251, 90894.5211, -117896.5694, 49351.7337, 6732.1589, 7925.9692, 9139.0043, 5435.0819, 8784.0331, 2490.8873, -786.0000, -135.7384, -4369.0000, -2146.0597, 0.0000, 0.0000, 7326.0000, -244.2695, -103.5000, -9.1512, 0.0000, 0.0000, 744.5000, -78.3806, 744.5000, -78.3806, 41.5000, 4.4196, -396.0000, -168.8610, 885.5000, -2456.6036, -269.0000, -43.0331, 738.0000, 305.1140, 0.0000, 0.0000, 1375.5000, 12391.5685, 2.0000, 1.7857, 2144.0000, 296.4426, -46774.0000, -4975.7126, 2144.0000, 296.4426, 0.0000, 0.0000, 501.5000, -1234.8288, 3905.0000, -542.9068, -5430.5000, -4386.0833, 33.5000, 59.3694, 276.0000, 121.4256, 0.0000, 0.0000, 276.0000, 121.4256, 0.0000, 0.0000, 650.5000, 2.5843, 0.0000, 0.0000, 725.0000, 548.4234, 0.0000, 0.0000, -4523.0000, -416.4257, -198.5000, -279.4521, -4954.0000, -474.9834, -433.5000, -235.7917, -1360.5000, -95.1978, -153.0000, -68.7836, -4.5000, 14.6603, -98.0000, -26.8160, -4782.5000, -254.0460, -68.5000, -80.2815, -10164.5079, 5810.6264, 173304.9891, -62384.9929, 0.0000, 0.0000, -7155.9961, -3885.2244, -22481.5086, 30374.2156, 0.0000, 0.0000, 0.0000, 0.0000, -15316.9999, 14379.1513, -12460.0056, 61.8604, 0.0000, 0.0000, 0.0000, 0.0000, -61018.5000, -61604.4930, -11454.9882, -5208.5133, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2386.0000, 5141.6249, -62543.0405, -44232.1232, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 16244.4932, 26253.0316, 3906.9943, -60376.6681, 0.0000, 0.0000, 0.0000, 0.0000, 180.5000, -9605.9002, 98001.9881, 25057.6794, 0.0000, 0.0000, 2865.0000, -9530.6970, 128191.0079, -79365.2414, -41207.0000, -16366.3433, -16997.5251, 64437.6020, -402.5000, 79.2478, -32644.5000, -19751.6188, -12871.0000, -7339.1972, 4479.4943, 16550.0622, -11893.5040, -41770.4752, 47185.9960, -48456.8594, 0.0000, 0.0000, 139017.4874, 37106.6988, -136545.0126, -32107.2931, -57667.5000, 41270.4745, -118002.5078, 190459.7337, 0.0000, 0.0000, 0.0000, 0.0000, -24995.5000, 13960.8348, 39716.0039, -20329.8211, -24715.5040, -119039.5205, 122276.9857, -94486.3966, -32997.0000, -107533.5064, -11620.9999, -36885.9910, 32546.0000, -23255.4933, -107630.5200, -78619.0866, 0.0000, 0.0000, -79843.5057, -45009.1880, 43195.9686, 68493.1735, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1722.0000, -213.0043, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -35615.0000, -2351.0080, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -108963.0126, 1065.1157, 237513.9778, -36941.3698, 0.0000, 0.0000, -311.5000, -37967.6392, 9844.9961, 147435.6048, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 65951.5000, 81705.6929, -78302.0000, -34407.0846, 0.0000, 0.0000, 23211.5000, -12600.2724, -85548.0000, -16584.9095, 7951.5000, -1879.6440, 31876.9960, 8168.0877, -3689.5000, -5472.5484, 45222.4953, 995.4257, -1847.5000, -1251.8610, -13419.0000, -2025.0848, -72045.0324, -4015.7678, -4019.5024, -4019.5024, -4006.7970, -4019.5024, -12.7054, 8013.1118, 18975.0105, 7941.5842, 9924.5685, 1706.5085, 9050.4421, -2923.7944, 1165.9527, -34851.5170, 28214.4857, 16576.4687, -27048.5330, 15120.7354, -5406.0535, -14477.6501, -3813.4209, -2661.4471, -4766.1196, -11816.2031, -37185.0000, -8437.3588, -40884.5000, -6794.9032, -48941.4964, 170618.1916, -110440.4976, -13044.4818, -24304.5000, -2358.5792, 1664.0000, -1769.4345, -36565.5000, -10533.7847, -43317.0000, -12477.3564, 109813.0000, 1374.8953, -61734.2500, 409.3292, -11032.2500, -71825.6653, -122693.7500, -28759.7479, -204302.2500, -14464.1837, 77562.0000, -2500.0088, 39977.5000, -1303.4766, 77616.5000, -1488.8287, -59264.5000, -4860.2913, -139886.5000, -1540.7090, -59799.0000, -3817.4242, 22734.5000, 1611.8041, -160326.0000, -12369.5944, 3332.2500, -17571.2553, 165476.0000, 24423.9924, -7328.5000, -5952.9037, 316946.7500, -6035.5864, 130329.0000, -9298.4555, 317753.7500, -13545.0009, -40698.0000, 9288.3108, -33731.5000, -20222.6042, 139661.2501, 34361.3069, -168896.7500, 84301.0371, 229835.7501, 35410.5494, -170293.5000, -41054.0702, -81213.4988, -8853.2501, -94670.4988, -41823.0957, 15002.5000, -7219.7348, -8812.5000, 1820.4115, 47851.5000, 19667.8130, -11568.0000, -22348.3947, -17160.5000, -6318.2706, 25354.0000, -818.3695, -62130.0000, -2464.7560, -3392.5000, 4397.0757, -52732.4976, -186823.4881, 0.0000, 0.0000, -49492.0000, 8260.7376, 127702.7500, -58360.9455, 0.0000, 0.0000, 0.0000, 0.0000, 80618.2500, 31231.8460, 272379.2471, 96801.4454, 0.0000, 0.0000, 164627.5000, -66189.7195, 94813.2539, -2228.0598, 52383.2500, -48763.2717, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -224750.5000, -36484.9437, 291425.2531, -47532.4768, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -131.0000, -60.9302, 67450.0000, -22906.3276, 101053.7496, 14247.7563, 0.0000, 0.0000, 0.0000, 0.0000, 71326.5000, -23759.0491, -195406.0000, -72403.8205, 0.0000, 0.0000, 36708.7500, -20507.9635, 122147.5000, -52614.2131, -30274.7461, -38591.6714, 280959.7535, -8396.3696, -889.0000, 691.0561, 43752.0000, -8189.7425, -81321.5000, 7613.5143, -58647.2500, -3625.1276, 22186.0000, -2961.3794, 150150.7496, 29831.3633, 329531.0000, -52370.5268, -92096.0000, -964.9300, -14362.7476, -88474.6270, -75909.0000, -22627.0451, 42606.7496, 31713.4313, 0.0000, 0.0000, 0.0000, 0.0000, 18990.0000, -10369.0641, 85862.9971, 30202.7383, 40866.5000, 4227.4575, -42388.2500, -104092.9893, 32168.5000, 132.9601, -54184.7500, -3552.2871, -92069.5000, -28045.6090, -34491.0029, 3344.8714, 0.0000, 0.0000, -89281.5000, -3081.1435, 16015.5079, -108361.1943, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -58143.4950, 240250.8165, -19287.5000, -2909.9336, -8637.5000, -1257.2493, 0.0000, 0.0000, 0.0000, 0.0000, -122187.5000, -1826.0633, 979.0000, -522.9380, -6523.0000, -1092.1978, -7766.0000, 1837.9912, 0.0000, 0.0000, -129132.0000, -16305.4361, -10945.5000, -1173.7228, -25582.0000, -3219.1320, 138119.5062, -110213.7442, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -123407.5000, -45508.2469, 143602.9971, -96055.8059, -260899.5000, -9381.9464, -165726.0000, -18543.4041, 85005.7539, -8697.8690, 81334.5000, -108322.1951, 0.0000, 0.0000, 0.0000, 0.0000, -43965.7500, -11263.9995, -89246.0000, -23608.6866, 0.0000, 0.0000, -110825.2500, 7444.1943, -204873.0000, -13611.1478, -33702.0000, 9398.6597, -69171.0000, -13941.7828, -25736.7500, -8952.6960, -218677.5000, -33279.5400, 68887.5000, -478.0625, 85661.0000, 3622.1457, -134424.7464, -12986.7278, -15710.2217, -13145.7296, -8292.5539, -13916.6887, -7417.6678, -49121.7455, -64249.9362, -44110.0921, -24313.7199, -59809.0319, -39936.2163, 55472.8838, -24850.9903, -20280.4903, -24889.4903, -8262.9903, 38.5000, -51327.9679, -914.1580, -13013.3861, -277.8025, 3015.1268, -4649.9730, -16028.5129, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -286.0000, -696.7906, -24606.5000, -42192.7416, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -28394.0000, -20398.1656, 0.0000, 0.0000, -28394.0000, -20398.1656, 0.0000, 0.0000, -257.5000, -511.1456, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -517.5000, -176.8869, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -508.0000, -342.6830, -1592.5000, -188.4506, -5194.0000, 355.8583, -4046.0000, 1125.7153, 3328.5000, -5403.9609, -508.0000, -342.6830, 3170.0000, -5218.9740, 0.0000, 0.0000, 0.0000, 0.0000, -508.0000, -342.6830, 11903.0000, 25893.6773, -50402.0000, -42914.2734, 0.0000, 0.0000, -7477.5000, -6523.0337, 3288.5000, 4894.8993, 0.0000, 0.0000, 0.0000, 0.0000, 12580.0000, 107998.3907, -10055.0000, 111305.9500, 0.0000, 0.0000, 0.0000, 0.0000, -5651.5000, -49633.8908, 4970.5000, -3656.2528, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 2327.5000, 5679.9542, 35435.0000, -102348.5052, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -10347.0000, -40929.8189, -28392.5000, -288115.0440, 0.0000, 0.0000, 0.0000, 0.0000, -7134.0000, -14055.5562, 56194.0000, -33997.6296, 0.0000, 0.0000, 25073.5000, 124467.8044, -34870.0000, 13078.7670, -7085.0000, -142936.8679, -11418.5000, 66021.5565, 0.0000, 0.0000, 4288.5000, 45716.5654, -444.5000, -281.4379, -3894.5000, -6147.2263, -6652.5000, -61542.0002, -32679.4961, -111446.6599, 0.0000, 0.0000, -2163.5000, -39591.4440, -24674.9961, 46294.2417, -1005.0000, 221.9328, -50825.5000, -115617.6576, 0.0000, 0.0000, 0.0000, 0.0000, 2562.0000, -3926.9875, -34292.0000, -98743.5910, 9726.0000, 31031.2179, -9821.0000, -20890.6581, -82.0000, -305.4839, 9333.5000, 10218.8273, 15970.0000, 68250.0325, 55914.0000, -79258.0844, 0.0000, 0.0000, 24947.5000, 19124.6134, 36156.0000, -72835.6633, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 985.5000, 9173.3165, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -82455.5000, -84373.8959, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1270.0000, 5313.4391, -49898.0000, 2153.0356, 0.0000, 0.0000, 8584.0000, 125135.9881, 8194.5000, 26365.0991, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -5103.5000, 30974.3001, 29726.5000, -9712.8222, 0.0000, 0.0000, 7075.5000, 19428.8177, -3638.5000, 26900.3796, -8345.0000, -63689.9401, 23291.5039, 35533.7205, 8.5000, 43.6954, -5319.0000, -33441.5510, 471.5000, 204.0076, 0.0000, 0.0000, -43369.4961, -5846.5614, -5814.6389, -5814.6389, -5892.6470, -5850.2282, 78.0081, -4442.1403, -5597.7203, -1960.9580, 1100.3138, -4321.7381, -6698.0341, 45447.3230, 70637.0118, 91424.5118, 64750.5118, 53249.0118, 5886.5000, -109708.4882, 2073.4897, 1556.7514, 2496.0958, 2433.3998, 2280.8668, -876.6484, -10361.5000, -17484.3346, -156574.0000, 734.6305, -32564.5000, -2294.8129, -61965.5000, -42617.9186, -6677.0000, -593.0662, -339.0000, 425.1574, -5513.0000, 2365.1457, -6655.5000, 2159.0741, 3737.5000, 30535.8254, -8562.0000, -937.5155, -59052.0118, -114050.9600, 39606.5000, -18086.4906, 112632.0001, 82842.2066, -3174.0000, -273.9189, 1070.5000, 122.1327, -7010.5000, -160324.1051, -27958.0000, -4787.5128, -202997.4999, -113533.6648, -30318.5000, -14583.0046, -239.5000, -50.6243, 83041.5000, 90696.8651, 26846.0000, 2525.2026, -31761.9992, -47385.8148, 699209.0000, 571335.7570, -11532.0000, -3191.0285, -2448.5000, -245.3259, -11899.5000, -3396.3780, -1314.0000, 22082.3019, 7867.5000, -9432.8929, -107624.0000, 15578.3419, -68562.5000, 41362.8676, -265102.5000, 7316.6890, -28311.5000, -33195.7722, -36459.5000, -45320.5298, -45643.5000, -26407.5792, -4474.0000, -3566.5011, -18891.0000, -6003.8195, -40949.9996, 15297.7903, -26667.5000, -15312.4327, -24021.5000, -6744.1243, -29785.5000, -2183.9507, -21487.0000, 204.6446, 16332.9960, 79157.7930, 1955.4845, -19939.4285, 1831.5000, 30.1263, -17339.5000, 23370.5287, -19905.0000, 14175.0606, 2319.5000, 38.1526, 25641.0000, 421.7680, 96557.9964, 105702.0809, -265906.9998, -62808.8918, 2380.5000, 39.1559, -57948.0000, -21589.1022, -1772.9996, 36860.9459, 52989.4964, 36871.5900, 0.0000, 0.0000, 0.0000, 0.0000, 1831.5000, 30.1263, 1831.5000, 30.1263, 0.0000, 0.0000, 23809.5000, 391.6418, 309147.5000, 123057.0570, -173676.0178, -38662.5924, 0.0000, 0.0000, 2327.5000, 38.2842, 14652.0000, 241.0103, 1831.5000, 30.1263, 2358.5000, 38.7941, 4182.0000, 68.7888, 18803.0004, 50027.0513, 44032.0000, 20328.3584, 0.0000, 0.0000, 0.0000, 0.0000, 66120.0004, 1742.2346, -62467.5040, -36586.9913, 0.0000, 0.0000, 63420.0000, -20249.8679, 16731.5000, -71597.5192, 203758.5000, 46009.1712, -79412.0079, -34030.2642, 1937.0000, -6010.4326, -14227.5000, -31492.1129, 10721.5000, 7709.3882, 15985.5000, 16202.9587, 58585.5000, 53019.2823, -139107.5036, -33222.3451, -56097.0000, -12590.9727, 29350.4964, -88720.6592, -80734.0115, -64287.0906, 171499.0000, 120813.2254, -435983.0159, -71183.8012, 1831.5000, 30.1263, 139834.0000, -74291.6174, 175574.0000, 115058.4072, -107602.0071, -74775.2958, 111361.4960, 131680.7631, 38114.0005, -29568.1626, -27694.5000, 7687.9478, -3522.0000, -1523.9513, 211465.5000, 78552.8950, -43460.5027, -29161.6897, 0.0000, 0.0000, -3325.5079, -15406.7024, 32351.9965, 55689.5030, 0.0000, 0.0000, 0.0000, 0.0000, 111721.5000, 1837.7036, -276938.5000, -7987.6698, -2041.0000, -420.4693, -1395.5000, -306.7008, 0.0000, 0.0000, 0.0000, 0.0000, -427.0000, -33.5924, -7583.0000, -6982.8165, 4872.5000, -322.7334, -289.5000, -35.3612, 0.0000, 0.0000, -5685.5000, -1177.4336, -662.5000, -101.3821, -981.5000, -143.4348, 11379.4892, 131117.3003, 23809.5000, 391.6418, 0.0000, 0.0000, 0.0000, 0.0000, 364198.0000, 251679.9064, -208362.0188, -207320.9420, -4179.5000, -1806.4896, 37319.0000, 33988.0622, -12076.0040, -42753.6045, -132476.0000, -83948.4566, 0.0000, 0.0000, 0.0000, 0.0000, 102330.0000, 58164.9296, -16820.5000, -35561.2700, 0.0000, 0.0000, 16600.0000, 6483.3372, 15901.0000, 5459.6798, 12964.0000, -3223.1177, 41177.5001, 37064.1073, 94011.5000, -69651.2094, -30741.5040, -3578.4779, 21133.0000, 21931.8076, -13699.5000, 128.1031, -55384.5030, 4381.0897, 4397.3676, 4424.0910, 4609.7123, 4440.2040, -212.3447, 38343.6649, 46132.9179, 38904.6477, 22162.1575, 30852.0883, 23970.7604, 27779.2255, -88657.6546, 168703.3454, -40574.1595, -51684.6546, -48083.4951, 92065.8488, 14231.6750, 17333.5232, 13322.4128, 10247.6868, 13478.3596, 7085.8364, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -22054.0000, 80537.2865, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -38219.5000, -162942.1429, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -18.0000, -754.5455, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 14588.0079, 17041.8093, -35394.0035, 1654.2423, -81886.0000, -24858.1194, -22340.5000, 25372.2634, -11229.5057, 51652.3100, -5864.5029, -5090.2463, -5420.0000, 66014.4768, 88726.0000, 78592.9861, 64869.0000, -59495.1079, 23634.0000, 45291.7547, 92.5000, -42912.9151, -717.5000, -1962.9590, 0.0000, 0.0000, 12283.0000, -34629.1557, 6333.5000, 38835.1887, 0.0000, 0.0000, 0.0000, 0.0000, 2206.0000, 7125.0931, 1026.5000, 2861.0372, 0.0000, 0.0000, 0.0000, 0.0000, 1293.5000, 563.4951, 297.5000, -730.9658, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 369.0000, 6460.9737, -963.5000, -2568.2598, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 456.0000, 807.7007, -4156.0000, -9959.9900, 0.0000, 0.0000, 0.0000, 0.0000, -4559.0000, -49995.8505, 3734.0000, 37751.2098, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 2506.5000, -19584.7517, -720.5000, -1534.5201, -45.0000, -2.8846, 0.0000, 0.0000, 0.0000, 0.0000, 6876.5000, 30043.4033, 4200.5000, 3930.8867, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 3316.0000, 2930.7114, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -60291.5000, -83159.4019, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1094.5000, -4558.4366, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -97.5000, -1490.3388, 27712.5000, 12704.4734, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -307545.0064, 871.0011, 871.0011, 871.0011, 871.0011, 871.0011, 0.0000, 20807.4546, 18558.4521, 21012.9783, 11131.6735, 25998.6688, 7426.7786, 48833.7649, 36221.0061, 49447.5090, 30371.0011, 53673.0011, 5850.0050, 31929.9957, -1916.2466, -1435.6500, -1764.2500, -3620.5833, -1818.2500, 2184.9333, -4210.0000, -1090.4005, -254879.0000, 63348.6893, 22794.0000, -66.5061, -153796.5000, -99652.6116, -42603.0000, 4743.6956, 13964.5000, 1681.2583, 75403.5000, 42446.8430, 77151.5000, 42463.6073, 14330.5000, 17167.1632, -132280.0000, 23476.5819, 121657.5008, 42081.2575, -3333.5000, -2090.7814, 130668.5004, 15446.5700, -62772.5000, -12444.6491, 6548.0000, 424.2534, -7504.5000, -1745.5630, 67848.0000, 2792.1316, -11414.4959, 15680.6232, 66278.0000, 2777.3406, 31989.0000, 220.8626, -172310.0000, 38824.0191, 479698.0008, 49657.4446, -306535.4996, 19148.5012, 107137.0000, 20884.3638, 29242.0000, 18997.8290, -85476.0000, -3167.1761, 33859.5000, 19016.9382, 4899.0000, -1017.7523, 44330.5000, 14409.5460, 8605.5000, 177.6207, 4093.0000, -6065.2971, 8776.0000, 186.1952, 30723.0004, 9714.6176, 30885.0000, 33064.9453, 37241.0000, 10347.4448, 10104.5000, 7335.9222, 52233.5000, 10529.7724, 1449.5000, 1770.4781, 30431.5000, 1322.1585, -640.4996, -9778.8827, 9026.5000, 1785.0996, -3480.4996, -2165.1520, 415874.5000, -3951.4377, -175737.9992, -35555.1118, 0.0000, 0.0000, 169094.5000, -1874.0926, -35534.5000, -48537.8151, 0.0000, 0.0000, 0.0000, 0.0000, 28822.5008, -43996.8026, 118995.0008, 23462.2658, 0.0000, 0.0000, -203167.5000, -4308.3255, -13355.4996, 3649.8063, -17424.9992, -117452.7120, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 47008.0004, -2115.5503, -303980.9972, -34837.0412, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 8231.0004, -30563.6456, -55499.4984, 21374.9555, 0.0000, 0.0000, 0.0000, 0.0000, -3833.0000, 3837.1201, 161524.0008, -38471.5307, 0.0000, 0.0000, 55994.5000, 7902.4990, 55247.0000, 18440.3080, 30979.5004, 12059.0761, -99337.9972, 713.5805, 14649.0000, 1712.4313, -19431.5000, 156.0601, 9776.0000, -1486.1389, 11635.5000, -5824.1787, -12476.5000, 2675.8765, -89618.4992, 12636.7516, -203167.5000, -4308.3255, 59882.5004, 6512.6794, -177459.4984, -16127.1717, -118891.5000, -6299.7891, 207058.0012, 43393.9444, 0.0000, 0.0000, 0.0000, 0.0000, -20621.0000, -4385.4270, 48818.5028, 40794.1811, -82911.9996, 9974.4522, -55383.0000, -100198.2646, 75985.5000, 114.9299, -55870.9996, -6545.8289, 3331.5004, 4338.3523, -81582.4980, -48955.5717, 0.0000, 0.0000, -37119.4996, 32637.8235, -71632.9988, -62741.4480, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -156724.9984, -52676.0063, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 4810.5000, 18.4804, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 12828.0000, 49.2810, 0.0000, 0.0000, 1603.5000, 6.1601, -33417.9935, 324568.5903, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 20102.5000, 3402.6588, -71310.4988, -1488.4720, 54902.5000, 12493.9080, 48507.5000, 13928.2500, -31762.9984, -15382.9190, 38349.0000, 90.3963, 0.0000, 0.0000, 0.0000, 0.0000, 5190.5004, 3869.9137, 39898.5000, 6339.3858, 0.0000, 0.0000, 9767.5000, 755.1550, 90567.0000, -66540.7844, 9253.0000, 903.9531, 94697.0004, 4694.4147, 23301.0000, 204.3557, 23405.0000, -14613.9529, 21434.0000, 7059.1864, 4057.5000, -9603.2100, 29768.0008, -548.0025, -488.3836, -501.4713, -646.2969, -435.9120, 157.9133, 10727.3640, 11452.5856, 11555.8878, 9842.5516, 13276.1445, 1610.0339, -137912.6490, 14198.5312, -27705.9688, 71183.5065, -10462.9935, -56984.9753, 141876.0377, 1145.9514, 1081.6622, 969.9320, 1512.3624, 1292.2010, -430.7002, -7908.9980, -10162.9197, -322246.9321, 8955.9087, -148588.9964, -36067.1022, -169267.0006, -1167.6488, -33617.5160, 4689.7854, 186413.5004, -2.0563, -34236.5163, 43326.6003, -45721.5163, 43553.8641, -220682.0000, 3329.3421, -241974.2535, -29706.5699, -186074.7755, 64109.9744, -305783.2186, 15869.5004, 65377.7316, -24645.1461, -250773.0000, 6947.5691, 188766.0101, 3457.2203, 242115.0039, -2370.6336, -32780.0165, 3033.9731, -258774.4958, -15843.9316, -39168.5165, 3745.2732, 58951.5000, 3451.0801, -553757.0091, -21905.2308, 420961.7451, -480.6656, -329659.0543, 15397.0035, 828174.5178, 31151.1732, 328821.2244, -26905.7724, 71337.9614, 5841.2967, 367560.2244, -26628.5314, -13410.0000, -928.9420, 246601.5091, -18043.0303, -73909.7303, 1631.1334, 3612.7950, 25171.4096, 3690.7697, 1833.9973, -66795.1474, -32343.0787, 331997.8893, -3180.6042, 43272.4971, -29188.1547, -119640.5172, -1761.7587, 106813.4943, -10634.8506, -164357.5045, -13252.2830, 26697.4886, -17618.0033, -71161.5053, -9409.7007, -291468.0018, -1087.1644, -95242.5025, -2781.1504, 75342.4795, 44475.7570, -146062.3862, 50361.3113, 1831.5000, 29.7902, -77440.4960, 17402.1466, -113982.8002, -18491.1050, 2319.5000, 37.7277, 25641.0000, 417.0625, -301023.7601, 40373.7167, -105570.2803, -2176.6641, 2380.5000, 38.7199, 667696.5039, 24393.9288, -244916.7691, -2906.2513, -49976.7439, -22058.8262, 1831.5000, 29.7902, 0.0000, 0.0000, 1831.5000, 29.7902, 1831.5000, 29.7902, 0.0000, 0.0000, 25641.0000, 417.0625, 497310.0006, -43636.6937, -280359.3635, 102168.7130, 0.0000, 0.0000, 2327.5000, 37.8578, 14652.0000, 238.3214, 1831.5000, 29.7902, 2358.5000, 38.3621, 4051.0000, 42.2347, -114742.5017, -8996.2472, 158965.7541, -40638.2365, 1084.0000, 17.6318, 0.0000, 0.0000, 289030.9927, -8416.1416, 277732.4577, -47299.1971, 0.0000, 0.0000, -267352.7488, -12001.9540, -86735.9634, 17547.8629, -140866.2405, -26293.4556, -133674.7632, -3977.1985, 45123.0000, 3822.5096, -47292.5079, 3813.4541, -186679.5000, -850.0287, -73744.2400, 1954.7855, 16485.9960, -464.0838, -50245.2143, 31158.8282, 556319.4247, 59318.8547, 45100.4707, 23772.2223, -30316.3071, 54660.6730, 246102.9958, -27058.1090, -84749.3239, 52694.3151, 1831.5000, 29.7902, 137893.0000, -75240.6295, -67794.0079, -34367.2766, 21857.9632, -16372.6355, -65597.0040, -34167.3086, 198548.7126, -27794.5904, -48297.5000, 12995.9101, -180484.7524, -3424.2495, 472145.5044, -24683.9431, -43135.5703, -38731.0375, 0.0000, 0.0000, -5278.5183, -24304.8385, 72353.4706, 40174.5349, 0.0000, 0.0000, 0.0000, 0.0000, 111713.0000, 1815.7225, -8188.6306, -2271.7262, -22065.5000, -1338.1111, -45810.5000, -1259.1045, 0.0000, 0.0000, 0.0000, 0.0000, -146395.5000, -2081.1076, -43784.5000, -2576.5372, -47091.5000, -1641.6750, -10369.5000, 833.0869, 0.0000, 0.0000, -164469.0000, -7922.7524, -18034.0000, -890.6148, -35827.5000, -1837.1337, 54203.4509, -61678.3697, 23809.5000, 387.2723, 0.0000, 0.0000, 0.0000, 0.0000, 272609.9926, -11375.7268, -25782.0741, 38951.1821, -24126.0000, 74192.8811, -101089.4961, -6297.8980, -168340.7411, 12570.0917, -199545.0000, -66601.1012, 0.0000, 0.0000, 0.0000, 0.0000, 376601.2504, 26305.4281, -35514.0041, -43551.2753, 10989.0000, 178.7411, -75751.2567, 20878.7184, -344306.0079, 8721.7891, 75455.0000, 11475.0359, -267831.9799, 33455.1478, 337039.7500, 5933.3185, -51033.0075, 10589.5646, 164966.5000, 992.1715, 121955.5000, 6455.6559, 15754.5558, -11592.4208, -4423.8708, -1755.5618, -4579.5432, 13216.9936, 155.6723, -8371.2906, 20719.8096, 62226.4312, -5863.5981, 175538.9958, 26583.4076, -34083.9754, -1176.2807, 769.0368, -16891.9433, 33244.5582, 15715.6626, 27084.3961, -1106.7196, -14855.5645, -1937.8542, 890.8191, 1631.5913, -15746.3836, 8391.5000, 399.7799, 146550.5000, 5810.3076, -23565.5000, -8998.2054, -89564.9988, 3117.2526, 23545.5000, -14339.9149, 4650.0000, -7688.9567, 315252.5000, 15725.7225, 315774.5000, 16460.1055, 10424.0000, 31322.6998, -323098.0000, -52572.9648, 109097.0000, -87243.0379, -681783.5000, -8862.7748, 51490.0000, -41228.5003, 19101.5000, -61200.7006, 2146.5000, -867.9212, 49657.0000, 15970.7535, 11211.0000, -25405.7144, -76240.5000, 17670.3101, 10503.5000, -26324.1242, 1388.5000, 3573.8409, -23393.5000, 45812.8546, 215449.5000, 253025.2344, -131027.5000, -96002.9862, 70951.5000, -6467.7590, -23807.0000, -11957.0603, -5980.5000, 17012.3519, -14128.5000, -7143.2016, 5742.5000, -411.0672, -96972.0000, 31272.7527, 12013.0000, -1089.1603, 186536.5000, 22395.7750, -8045.0000, -2367.8747, 406355.5000, -22058.8910, 21969.5008, -19354.7846, -9618.4996, -59289.8303, -37867.0000, 14798.6019, 132690.0000, 15644.1726, 73197.0000, 31803.5024, 167947.0000, 27986.5941, 16577.5000, -3908.5937, -101518.0000, 30733.6742, -41473.5000, 44784.0753, 673938.5000, 104018.2447, 28691.5000, 46071.7158, 0.0000, 0.0000, 671053.5000, 48994.7144, 18850.5000, 39662.3101, 0.0000, 0.0000, 0.0000, 0.0000, -45556.0000, 35862.1777, -96589.0000, 35038.0753, 0.0000, 0.0000, -63141.0000, -9778.1378, -97473.0000, -20965.9465, 7569.0000, 70767.7824, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -94199.0000, -39422.5476, -330867.9988, -433.4172, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 119121.0000, 49551.5976, -224687.0000, -74276.2223, 0.0000, 0.0000, 0.0000, 0.0000, 295422.0000, 57170.9571, 254498.0000, -52896.1851, 0.0000, 0.0000, 224211.0000, -18646.5991, -108223.5000, 38570.9051, -47143.0000, -937.8655, -253482.0000, -159487.4516, 23362.5000, 1739.5853, -75876.0000, 14928.6481, -65321.0000, 8021.4771, -6226.5000, 927.8063, -33033.5000, -41066.1708, -224268.4988, 110482.1213, -50085.0000, -9740.7942, -51921.5000, -60752.3035, -131739.0000, 50787.4593, -94866.5000, 42023.7016, -62877.4988, -95244.4883, 0.0000, 0.0000, 0.0000, 0.0000, -145699.5000, -40750.0406, -129003.0000, -10119.4877, -152678.5000, -33514.2427, -156694.5000, 25309.9790, 326511.5000, 36331.2598, -43361.5000, -7937.8455, -57240.0000, -3990.2676, 145563.5000, -48812.8706, 0.0000, 0.0000, 156077.5000, -59149.9743, -302606.0000, -109312.1859, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -161628.5000, -234758.5875, -13.0000, -6.3725, -383.5000, -27.3658, 0.0000, 0.0000, 0.0000, 0.0000, -13.0000, -6.3725, -1703.0000, -2018.1705, -4656.0000, -2272.3922, -13.0000, -6.3725, 0.0000, 0.0000, -49.0000, -37.6454, 13.0000, -4.9454, -1718.5000, -464.9752, -600.9988, 3190.4231, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 34602.5000, -40567.8447, -16114.0000, -125837.6103, 16047.0000, -1902.7430, 83341.0000, -3035.7786, -191020.0000, 11104.0757, -1194.0000, -1584.6435, 0.0000, 0.0000, 0.0000, 0.0000, -18146.0000, 50140.7481, 39126.5000, 7882.1419, 0.0000, 0.0000, -136050.5000, -30103.1165, 40630.0000, -10170.8099, -19625.5000, 8444.6901, -22984.0000, -39466.7443, 77210.5000, 15647.2241, -85697.0000, -84285.2469, 54344.0000, 5282.3569, -62326.5000, 21394.7298, -12662.9988, -3153.0576, -3920.2784, -3251.0967, -1649.0152, -3319.8102, -2271.2632, -37017.7869, -46662.1391, -37416.7967, -11339.5683, -42075.8950, -35322.5708, -117130.7331, 5249.5020, 97759.0020, 77727.5020, -30423.9980, -72478.0000, 122519.5061, -1022.2416, -950.0471, 478.4632, -3067.8028, -7417.9450, 2117.7556, -358.0000, -13.9953, 499108.0000, 172567.4129, 271.0000, -339.1402, -117407.5000, -80912.6627, -149.0000, -4.4269, 0.0000, 0.0000, -20483.5000, -31161.7720, -20849.5000, -31160.8152, 1478.0000, 404.5764, 15786.5000, 11456.6840, -98958.0000, -75875.4528, 393.5000, 111.1309, 981.5000, 554.2576, -5012.0000, -195.9343, 140.0000, 67.3479, -382.5000, -16.5552, -4845.0000, -22651.7461, 263.0000, 204.0384, -4846.0000, -22652.3414, 0.0000, 0.0000, -155780.0159, -28806.3701, 244392.0000, 62091.6243, -8219.0000, 10943.4666, 534174.0000, 155991.8823, 22052.0000, 19063.3994, 2176.5000, 681.8543, 21873.0000, 19056.4017, 1.0000, 0.5952, 65549.0000, 7512.0723, 0.0000, 0.0000, -4677.0000, -185.5450, -358.0000, -13.9953, 5909.0000, -2271.9511, -19259.5000, -6249.7385, -21036.5000, -28457.5374, -920.5000, -13499.2562, 56542.5000, 4736.7091, -2282.0000, -540.4496, 56738.0000, 5909.9111, -985.5000, -157.5199, -3203.0000, -7486.7950, -1490.5000, -103.9138, 367847.5000, 35682.2999, -214989.0306, -81606.1684, 0.0000, 0.0000, 56933.0000, -9879.5923, 16419.9972, 11649.9379, 0.0000, 0.0000, 0.0000, 0.0000, -2183.5074, 83657.7637, 2687.9921, 62648.8749, 0.0000, 0.0000, -16164.0000, -637.8848, 161815.9914, 44101.3426, -289879.5187, -52696.9230, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 609593.0000, 125762.4573, -697884.0457, 118865.7028, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 85783.5000, 7829.7866, -36558.9988, 6187.8418, 0.0000, 0.0000, 0.0000, 0.0000, -21209.5000, -38951.8006, 78391.4952, -68362.9094, 0.0000, 0.0000, 37655.5000, 3130.4258, -185595.9992, 22118.7500, 179506.0012, 1521.3317, -300353.5209, -147806.5858, -8618.5000, -30597.0488, 15773.5000, 7481.1812, -12276.0000, 1481.6677, 78824.0000, -25755.0303, 128804.0000, 68088.0581, -139303.5127, 52558.4224, -16164.0000, -637.8848, 269477.5000, -1761.4102, -333618.5199, 15094.0678, 63066.9972, -66001.7267, -117848.5372, -15528.5123, 0.0000, 0.0000, 0.0000, 0.0000, 221810.5000, 93230.6572, -63221.0113, -104005.4297, -2824.9988, -37933.3245, -61792.5119, 13459.2303, -10401.0000, -4720.1874, -7158.5000, -14491.8830, 265884.5000, 70831.6859, -142573.5386, -176749.3164, 0.0000, 0.0000, 384124.0024, -43435.8127, 1896.4747, 27153.7071, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -184096.5000, -6377.8560, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -280.0000, -229.5082, 949869.9841, 165848.5985, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 278427.5000, 78143.9318, -595777.5133, -153137.1059, -67.5000, -10.1199, 45445.0000, 38730.6031, -292377.0130, -12128.9257, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -54858.0000, -9170.3299, 86471.9921, 1121.2314, 0.0000, 0.0000, -61871.0000, -15170.5108, -135676.5040, 36226.1191, 16036.5000, 11288.8963, -97915.0000, 31375.4826, 65855.5000, 7171.5230, -210833.0000, -31841.0740, -5443.5000, -1475.1689, -7879.0000, 6410.9649, -197464.5314, 553.1611, 530.8829, 531.4901, 493.8192, 533.1329, 37.0638, 11262.5562, 27800.4714, 9964.8592, -1236.9722, -16784.3667, 29037.4436, -6444.0935, -58977.1231, 58590.9090, -21300.5406, -75411.0377, -37676.5825, 227164.6458, 3991.2732, 3460.6620, 7813.4768, -1707.7061, 4880.5296, 5168.3681, 107884.0000, -46012.3543, -140737.0000, 2153.8200, 107485.5000, -80432.1448, -125502.5000, -18568.6833, 68090.5000, 13847.7264, 127922.0000, 9100.0511, -122736.0000, -28636.5533, -133553.5000, -26848.1881, -282763.0000, 70143.9688, 37389.5000, -37452.1227, 144042.5008, -220437.8064, -822146.4843, 107568.6039, 19693.0043, 47924.8119, -192133.0000, -32343.8015, 97043.5000, 9564.0387, 98598.5000, -5082.9538, 39133.5000, -6535.1576, -255346.9959, 124553.2461, 36221.5000, -6214.5097, 25065.5000, 8398.5137, -59220.5000, 35743.0317, -242739.0000, -33094.3799, 312261.4925, -36917.7274, 7059.5020, 85859.4510, 487236.0000, 37207.8034, -41272.5000, -12244.2419, 527433.0000, 34462.4411, 28393.5000, 1075.9918, -88927.0000, -6851.9732, 18633.5000, 12921.5474, 24499.5158, -51211.4569, -16639.5000, 1511.6793, 118089.4918, 83086.9139, 282017.5000, -32123.4247, 133193.4943, -4525.5048, -80271.0114, 113834.4464, 131549.0000, -24959.1092, 25893.4971, 18432.1492, 78493.9886, 61727.2501, -79288.0053, 18196.6339, -288763.0057, 26356.7008, -41715.0025, 9199.8101, -362358.0000, 257703.0939, 53388.6649, 98040.2529, 0.0000, 0.0000, 318558.0000, 86114.5152, -38851.5143, 37963.4095, 0.0000, 0.0000, 0.0000, 0.0000, -260947.9953, 75293.9512, -186057.4999, 138296.8736, 0.0000, 0.0000, 321570.5000, -19247.0836, -237866.4992, -35118.6357, 14944.0051, -30802.2531, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -244338.4996, -42597.7370, 318278.5161, 34183.4405, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 136933.0008, 43020.7995, -103006.5037, 16981.0886, 0.0000, 0.0000, 0.0000, 0.0000, 195229.5000, 31154.0447, 212700.5008, -117360.3166, 0.0000, 0.0000, -24208.0000, -6111.6573, -140210.4913, 74436.4036, -92402.4996, 1665.6449, 17471.0146, -34192.9817, -25799.0000, 4953.0594, 112749.0000, 20662.8383, -67424.5000, 121226.6470, -30543.5000, 42834.4216, -242232.0000, -31003.4577, -144938.4827, 67226.2029, 0.0000, 0.0000, 17293.0004, -131587.1459, 346552.0095, 22089.1309, 107860.5000, 39804.1854, 91042.5198, -51997.2006, 0.0000, 0.0000, 0.0000, 0.0000, -208812.5000, -46959.1360, -165179.9806, 26613.3923, 2814.0004, 28130.9273, 6385.5165, -56693.5049, 239967.0000, 73013.1535, -72246.0000, 4885.3222, -141205.0000, -70377.4603, -164335.9936, -124596.7441, 0.0000, 0.0000, 30781.5008, -56222.6162, -142923.9944, 125372.9429, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -22984.9943, -109438.8306, -247.5000, -288.6557, -12768.5000, -231.2638, 0.0000, 0.0000, 0.0000, 0.0000, -23068.5000, -514.4165, -562.5000, -37.7239, -620.5000, -10.9449, -2016.0000, -51.4024, 0.0000, 0.0000, -27054.5000, -520.2830, 6.5000, 17.8622, -313.0000, -177.2126, -105654.4647, -72495.6585, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -69845.9961, 84285.3096, 377402.5260, 85170.2880, 262458.5000, -45.7501, -43675.5000, 1837.5157, 62671.0008, 11367.9071, -150949.5000, -4587.2057, 0.0000, 0.0000, 0.0000, 0.0000, -14389.9996, -41826.8615, -51195.0000, 99374.9139, 0.0000, 0.0000, 93130.5000, -15193.5355, 73525.5000, 108638.4798, -8787.5000, -12743.1395, -202175.9957, 78544.5019, 18994.0000, 20541.2574, 206301.0047, 54478.0695, 43446.0000, 13709.7265, -14478.5000, -2824.8065, 82279.5145, 13910.7886, 12982.3898, 12800.5782, 9668.1793, 15202.5731, 3314.2105, 19019.5269, 25092.4054, 12752.2286, 55125.1893, 12578.5376, -30032.7839, -45283.2431, -9663.9154, -19816.9945, 3888.4555, 22296.5672, -13552.3709, 11000.8237, 866.8324, -578.5719, 1957.7286, 3329.0777, -4664.4872, -3907.6496, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -5464.0000, -2849.0393, 99631.0000, 15127.1043, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -65265.5000, 3852.6223, 0.0000, 0.0000, -65265.5000, 3852.6223, 0.0000, 0.0000, -187.0000, 54.9179, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -550.0000, -164.4325, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -4816.5000, -2747.2244, 5469.5000, 1980.5726, 12374.5000, 22550.1139, 15636.0000, 23909.3524, 6298.5000, -16589.2229, -4167.0000, -1977.4949, 14258.5000, -14195.7913, 0.0000, 0.0000, 0.0000, 0.0000, -4119.5000, -1953.9801, 1221.5000, -9761.6615, 33349.0000, 79478.4108, 0.0000, 0.0000, 15618.5000, 18763.2759, -210608.0040, -24851.0431, 0.0000, 0.0000, 0.0000, 0.0000, 32982.5000, 118208.7053, -363345.0040, -22149.9157, 0.0000, 0.0000, 0.0000, 0.0000, -3367.0000, -32856.0601, 49831.5000, 85349.7566, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2797.5000, 3633.9499, 2044.9960, 93277.6908, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -9508.0000, -5979.6385, -31214.0000, -61925.0985, 0.0000, 0.0000, 0.0000, 0.0000, -8724.5000, -6847.9801, 256899.5000, -39734.1893, 0.0000, 0.0000, 26214.0000, 56747.1039, -127879.0000, 16654.3890, -434.0000, -59186.0576, 97459.5000, -12276.5957, 41.5000, 10.3750, -226488.0040, 1794.8338, -2309.0000, -407.2389, -15081.0000, -16967.1881, -12068.0000, -54896.4907, 10598.0039, -59646.2824, 0.0000, 0.0000, 15651.0000, -41266.2184, 112790.5039, 5624.0878, -8819.5000, 14597.4653, 177689.5000, -67702.6125, 0.0000, 0.0000, 0.0000, 0.0000, -228371.5000, 8875.2215, 30262.9960, -8999.9551, -198880.5000, 11562.8694, -45792.5040, 2399.1496, -124.0000, -161.8933, 24668.0000, 8899.4230, 7103.5000, 51432.8017, 266765.5000, 10516.9592, 0.0000, 0.0000, 117059.5000, 92981.8764, 126153.9960, -54787.6148, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1123.0000, 9354.5728, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -37101.0000, 19873.7949, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 5615.5000, 58182.3649, -34206.0040, -89078.9318, 0.0000, 0.0000, 31144.0000, 18508.1664, 6846.5000, 75150.5861, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -6647.5000, 59200.4863, 50578.0000, -1794.0019, 0.0000, 0.0000, 1002.5000, 26240.5566, -57047.5000, -8933.1793, -24938.5000, -56158.3286, 13129.5039, -38565.8163, -3943.5000, -1098.6498, 134591.5000, 59382.0550, 991.5000, 120.1145, 3674.5000, 3835.2699, -53220.5000, 2366.6205, 2399.8571, 2399.8571, 2317.2012, 2364.2678, 82.6559, 13334.0845, 26757.7263, 15564.9374, 10186.9061, 9432.3578, 16570.8202, 43816.8072, -50934.5200, 20627.9800, 69380.4800, -54086.5200, -120315.0000, 34340.4800, 3272.5368, 7223.3010, 4365.7984, 580.4454, 1937.6854, 6642.8555, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -10.0000, -9.0909, -10.0000, -9.0909, 0.0000, 0.0000, 387.5000, 179.2685, -13474.5000, 38932.8992, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -3817.0000, -877.3382, 0.0000, 0.0000, -3790.5000, -724.0487, 0.0000, 0.0000, -2383.5000, -790.4311, 0.0000, 0.0000, 0.0000, 0.0000, 3853.0000, 102.6084, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -3548.5000, -2175.2365, 0.0000, 0.0000, -15.5000, -5.5160, 0.0000, 0.0000, -742.5000, -340.7995, -575.0000, -2463.4793, -34139.0000, -17631.5957, -28131.0000, -12399.9229, -7022.5000, -15148.8879, -2292.5000, 247.1445, -11106.5000, -17323.9580, 0.0000, 0.0000, -191.0000, -632.2641, -607.5000, -53.0146, -2605.0086, 101103.0928, -63150.0086, 86820.9340, 0.0000, 0.0000, -10321.0000, 10439.0185, 91194.0000, 152949.3531, 0.0000, 0.0000, 0.0000, 0.0000, 96685.0000, 91797.9849, 22368.0000, 31801.0971, 0.0000, 0.0000, 0.0000, 0.0000, -8387.0086, -4178.3125, -95802.5000, -75460.8708, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 50396.5000, 134726.2678, 116285.5000, 173480.0106, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 498.0000, 18418.6022, -15197.5000, -4683.5711, 0.0000, 0.0000, 0.0000, 0.0000, 7811.0000, -11325.8207, 471.0001, -75429.8002, 0.0000, 0.0000, 32295.5000, 65356.4307, -11661.5000, -37910.9882, -73679.5000, -69777.8583, -28721.0085, -46.3934, -945.0000, -1178.5977, -12421.0000, 29312.8288, -27611.5000, -8364.2145, -10498.0000, -2927.3538, 9442.5000, 17888.8388, 88006.0000, 221157.0598, 0.0000, 0.0000, -65898.0000, -99924.6992, -24881.5086, 64172.3676, 2978.0000, -10861.1091, -256.0085, -30550.0482, 0.0000, 0.0000, 0.0000, 0.0000, 6061.0000, 17568.9368, 57741.4914, 192827.1278, -35917.0000, 57569.6617, 64002.9828, 152965.5834, -3151.5000, -1609.9705, 2052.0000, 5141.4567, 33896.5000, 151517.8864, -105080.4999, -56484.4575, 0.0000, 0.0000, -18692.5000, 15918.6432, -92152.4999, 49161.3068, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -86.0000, -38.5234, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -22809.0000, 34624.0237, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 35274.5000, -50411.5148, 34954.0001, -140003.7451, 0.0000, 0.0000, -10050.5000, -24234.0447, -32506.0000, 31613.4437, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -21776.0000, 1337.9409, 24766.5000, -1602.2203, 0.0000, 0.0000, -18044.5000, 14416.5982, -38568.0000, 20792.3991, -11780.5000, -1574.1851, 51420.5000, 24717.4049, -669.0000, 7314.5807, 18650.0000, 44568.8126, 3427.0000, 4398.7582, 7499.5000, 2696.3458, 41442.4915, 12542.6481, 12542.4972, 12542.4972, 12543.5279, 12542.4972, -1.0307, 45235.1340, 47375.0923, 54879.8963, 37074.0676, 52812.2238, 10301.0246, -7364.0630, 160526.4747, -19147.0253, -110330.0253, 75789.9747, 270856.5000, -89950.0768, 3720.7563, 1862.3177, 3231.1591, 4092.8697, 3127.1023, -2230.5519, -52.0000, -1587.5000, 0.0000, 0.0000, -46408.4980, -4114.4248, -70.0000, -2333.3333, -3339.0000, 61835.8523, -4594.0000, -98473.2953, -56485.5000, -61594.3173, 12428.5000, 13385.0982, -709.5000, -24792.5000, -5776.0000, 33448.8156, 2317.0000, 179028.8106, -46857.0000, -25603.1654, 0.0000, 0.0000, 268.5000, 0.2588, -893.5000, -735.2457, 2281.0000, 2.1990, 1595.4943, 3463.0287, 1369.0000, 1.3198, 0.0000, 0.0000, -1757.0057, 67.4180, -1267.5057, 199.0003, 4176.5000, 4.0264, -798.0000, -290.5435, -21327.5000, -62268.4956, 236989.5000, 98052.3524, 16170.9943, -59085.8986, 0.0000, 0.0000, -2219.0000, 5305.9850, 0.0000, 0.0000, 964.5000, -87.5862, 202794.5000, 69356.3534, 2419.0000, -204.2660, 0.0000, 0.0000, -412456.5090, -276095.0004, -619.5000, -311.4628, -7154.5000, -472.6444, 268710.5000, 88776.1154, 55271.9891, 181668.8822, 0.0000, 0.0000, 55981.4891, 182378.3822, 636.5000, 0.6136, 1784.5000, 1.7203, 0.0000, 0.0000, 156454.0000, 57122.1666, 0.0000, 0.0000, 146942.3490, 32810.7894, 243454.3877, 85463.8086, 255239.5016, 81013.6415, 60759.4943, 28767.2750, 8074.5000, 12725.8755, 15580.5000, 24442.8911, -16223.0000, 3332.3473, 14352.5000, 9992.2874, -12743.0000, -32.9545, 15742.0000, 7636.8131, -28775.0000, -67520.4181, 240557.5259, 57157.4871, 0.0000, 0.0000, -295729.5000, -6172.5412, 19182.0079, -160630.8578, 0.0000, 0.0000, 0.0000, 0.0000, -108894.5000, 62205.7918, 268924.5080, 70019.3808, 0.0000, 0.0000, -2910.5000, -2371.9867, -17370.0000, -30354.9444, 195146.5173, -62270.6996, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -325696.0000, -60471.7881, 296086.0372, 37719.5639, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -190952.0000, -45300.9082, 168462.0101, -63861.6414, 0.0000, 0.0000, 0.0000, 0.0000, 225358.0000, -29118.2565, -357586.0079, -162029.2742, 0.0000, 0.0000, -205414.5000, -55617.7967, -35239.4802, 57274.6462, -205632.0000, -56117.0187, 154096.0139, -183872.6735, 8843.5000, 468.6694, 147240.5000, -17224.4089, 30005.0000, 19452.0800, 38942.0079, -59153.5804, 121090.0000, 19440.3155, 38924.5397, 44635.8816, -2201.0000, -1662.4867, -459592.0000, -26114.8158, -439788.5082, 80979.8144, -20428.9976, 13226.0583, 204373.4819, 44996.3184, 0.0000, 0.0000, 0.0000, 0.0000, -156564.5040, -15599.5424, 18063.4801, -66399.8007, 92813.5000, 5177.0776, -460803.0007, 11451.3086, -66118.5000, -1071.1364, -42465.0000, 4328.0534, -113020.5000, 58661.9463, 313274.0355, -130527.5637, 0.0000, 0.0000, -110334.5000, 66204.7536, -41918.0159, 21471.6726, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -13122.5000, -3855.4621, -40.0000, -7.4349, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -40.0000, -7.4349, 0.0000, 0.0000, 0.0000, 0.0000, -40.0000, -7.4349, 0.0000, 0.0000, -136.0000, -28.8089, -40.0000, -7.4349, -40.0000, -7.4349, 554427.4464, 284089.0331, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -499271.5000, -1771.2108, 94340.9955, 43641.1948, -512.0000, -27.5269, 29935.5000, 58421.1395, 3137.5158, -121948.8937, -1701.0000, -321.6754, 0.0000, 0.0000, 0.0000, 0.0000, 22685.0000, 13999.6436, -209499.5000, -164327.2593, 0.0000, 0.0000, -1766.0000, 9233.7166, 91234.5000, -21628.1965, 50665.0000, 4291.1236, 160938.0079, -26467.5639, -27358.0000, 4089.8940, -35679.5007, 63802.2409, 38870.5000, 742.4746, 88323.0000, 6183.9751, -2414.4973, -1909.4706, -1916.0024, -1916.0024, -1831.7938, -1916.0024, -84.2085, -12251.8610, -20547.3383, -11925.2427, 31656.8791, -13438.4798, -52204.2173, -55454.3298, -116559.5944, -28564.5121, 35908.9936, 25328.9406, -152468.5879, -24613.1518, 291.3284, -9297.9796, 1096.4201, 1074.3783, -1416.3235, -10372.3579)
    
    # 权重3，由网络采集的样本得到
    # Weighted feature vector generated from ModelTrainer.cs/ModelTrainer.exe during the training phase based on in-the-wild samples.    
    <#
        Accuracy / False Positive rate on training data = 0.9970 / 0.0003
        Test data:
        Accuracy: 0.9959
        Precision: 0.9937
        Recall: 0.9918
        F1Score: 0.9927
        TruePositiveRate: 0.2789
        FalsePositiveRate: 0.0018
        TrueNegativeRate: 0.7170
        FalseNegativeRate: 0.0023
    #>
    [System.Double[]] $commandLineWeightedVector = @(3.2928, 0.0000, 0.0000, -22.8000, -85.1915, 0.0000, 0.0000, 75.0000, 136.9834, 1.5000, 0.4270, 0.3000, 0.0253, 6.3000, -4.5099, 5.1000, -4.6106, 29.7000, 15.2249, 282.0000, 74.0275, 51.3000, 396.9474, 25.2000, 1.0706, 113.7000, 92.7415, 23.1000, 7.6821, 0.0000, 0.0000, 19.5000, 7.8850, 80.7000, 114.4592, -102.0000, -58.8352, 80.7000, 114.4592, 3.0000, 0.8541, 15.9000, 13.1461, 606.6000, 396.1669, -25.2000, -5.6230, 0.0000, 0.0000, 45.6000, 20.8949, 0.0000, 0.0000, 49.8000, 21.8496, 0.6000, 0.1770, 40.2000, 17.9320, 0.0000, 0.0000, 41.7000, 15.4380, 0.0000, 0.0000, 70.5000, -168.0319, 99.3000, -48.8620, 69.9000, 80.0108, 82.8000, 196.2393, 60.3000, -58.5855, 72.6000, 12.2455, 64.5000, 110.3633, 81.9000, 63.5537, 69.9000, 31.5874, 94.5000, 20.3125, 10.8000, 11.1077, -418.8000, -972.3948, 0.0000, 0.0000, 45.3000, 14.2236, 57.0000, 36.2535, 0.0000, 0.0000, 0.0000, 0.0000, -5.7000, 47.4370, -172.5000, -432.2043, 0.0000, 0.0000, 0.0000, 0.0000, 61.2000, 120.3857, -31.2000, -74.1364, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 41.4000, -15.1685, -289.8000, -374.9500, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 7.8000, -3.7170, -80.4000, -191.0658, 0.0000, 0.0000, 0.0000, 0.0000, -2.4000, -20.3168, -130.5000, -195.1958, 0.0000, 0.0000, 42.3000, 21.0303, 87.6000, 179.8652, 150.3000, 287.9065, -82.5000, 179.9649, 22.8000, 0.5345, 36.3000, 7.2450, 29.7000, 1.2830, 44.1000, 6.6067, 24.6000, 9.6688, -261.0000, -423.5384, 0.0000, 0.0000, -18.9000, -14.2206, -158.4000, -187.1061, 27.0000, 27.6694, -68.4000, -35.2358, 0.0000, 0.0000, 0.0000, 0.0000, 105.0000, 156.0291, -329.4000, -175.1023, 129.9000, 250.9080, 79.2000, -14.1517, 28.2000, 3.2320, 36.6000, 13.9435, 35.4000, -3.6247, -76.2000, -81.1776, 0.0000, 0.0000, 42.0000, 165.7817, -89.7000, -78.3050, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 255.0000, 116.5624, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1447.5000, 1289.6215, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 33.3000, 4.2935, -134.4000, -70.2671, 0.0000, 0.0000, 32.7000, -6.1032, -107.4000, 8.8538, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -0.6000, 4.3268, -6.6000, -103.4625, 0.0000, 0.0000, 38.7000, 7.3352, 86.1000, 40.1007, 31.2000, 3.5556, -3.3000, -14.2357, 37.8000, 3.0146, 9.6000, -49.6122, 39.6000, 3.0450, 28.2000, 4.6745, 46.2000, -3.7381, -3.5467, -3.5758, -3.9981, -3.6342, 0.4514, 20.1383, 31.7506, 28.2800, 2.3441, 19.1614, 29.4065, -622.8386, 339.3000, -126.0000, -1421.4000, 474.9000, 1760.7000, 1482.3000, 18.2305, 21.9123, 18.8786, 15.2147, 15.9005, 6.6976, 42.9000, -356.0000, 3.0000, 110.0000, 0.0000, 0.0000, -0.9000, -90.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.3000, 6.0000, 0.9000, 60.0000, 0.0000, 0.0000, 388.8237, -478.4676, 0.0000, 0.0000, 0.0000, 0.0000, 286.8000, 1798.8620, 0.0000, 0.0000, 0.0000, 0.0000, 86.4000, 41.0309, 46.2000, -117.7450, 675.6237, 243.0661, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 907.2434, 432.3057, 0.0000, 0.0000, 69.0039, 53.6313, -9.5961, 8.3599, 807.9013, 1446.5360, 0.0000, 0.0000, 0.0000, 0.0000, 457.2459, -1343.5627, 262.5405, 444.5872, 0.0000, 0.0000, 0.0000, 0.0000, 681.9079, -106.2724, 0.0000, 0.0000, -6.0000, 58.1336, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 2.7000, 0.7031, 0.0000, 0.0000, -219.5817, -906.3721, -9.6000, 49.6125, 0.0000, 0.0000, -92.2500, -375.0666, -16.7961, -22.4304, 10.5000, 7.2917, 52.8000, 32.9064, 0.0000, 0.0000, 27.3000, -34.5888, -4.5000, -58.9721, 57.3000, 89.5100, 183.3158, -379.1932, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 155.4079, 221.4912, 20.7000, -12.7846, 0.0000, 0.0000, 5.3856, -295.7081, 52.8000, 32.9064, 52.8000, 32.9064, 857.4079, 1254.1265, 976.5354, 798.1402, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 5.3856, -295.7081, -50.7072, -73.3538, 0.0000, 0.0000, 0.0000, 0.0000, 60.0118, -194.3943, 1279.2842, -1938.4520, -72.0000, -166.0147, 0.0000, 0.0000, -49.2000, -23.0313, -6.0000, -2.3438, -9.5961, 8.3599, 30.6000, 83.8390, 0.0000, 0.0000, -36.3000, -652.2271, 3.3000, -18.9565, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1741.5519, 1959.4537, 75.0000, 47.5581, -34.2000, -116.5714, 7.5000, 530.6154, 59.4000, 2576.7143, 9.9000, 65.4545, 31.8000, 296.3636, 0.0000, 0.0000, 0.6000, 15.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 6.9000, 625.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 6.6000, 21.4952, 0.0000, 0.0000, -74.4000, -1127.1429, 1.8000, 68.7500, -6.0000, 72.8648, 0.0000, 0.0000, 35.4000, 1566.7538, 10.5000, 95.4545, 76.5000, -291.4286, 0.0000, 0.0000, 0.6000, 15.0000, 6.0000, 124.0000, -30.9000, -956.7857, 0.0000, 52.0000, -62.7000, -488.0586, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 8.4000, -554.3996, 0.0000, 0.0000, 0.0000, 0.0000, 7.2000, 63.6538, 38.4000, 1595.3214, 25.5000, 123.8636, 1.5000, 37.5000, 9.3000, 222.0000, 771.6434, 1786.9761, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 13.2000, 37.4228, -144.8817, -716.9244, -4.2000, -3.0235, 2.1000, 10.6722, 0.0000, 0.0000, 0.0000, 0.0000, -28.8589, 202.6178, 92.7000, 175.5079, -49.3794, 30.2781, 0.0000, 0.0000, 1.8000, -31.2986, 0.0000, 0.0000, 0.0000, 0.0000, -158.6972, 206.5734, 0.0000, 0.0000, 0.0000, 0.0000, -112.8000, -136.8193, 6.3000, 13.6957, 156.9215, 338.4082, -36.9000, -19.8576, 0.0000, 0.0000, 0.0000, 0.0000, 12.6000, 27.3913, -36.6000, -50.9483, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -0.3000, -0.5172, -1.6794, 63.9491, -160.0794, -106.3528, -125.5812, -165.8270, -112.6812, -144.6015, 60.9018, 146.5811, -17.7000, -23.1956, 30.6018, 97.7495, -27.0000, -28.9988, -90.6000, -114.4636, -25.5000, -31.3948, 2.7000, 234.6616, -30.5961, 498.4709, 0.0000, 0.0000, 65.1000, 220.8660, -15.5882, -288.5410, 0.0000, 0.0000, 0.0000, 0.0000, 12.1206, 319.1063, -296.6842, -339.8383, 0.0000, 0.0000, 0.0000, 0.0000, 32.1000, 202.7515, -206.7589, -194.2541, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 666.6423, 742.7342, -484.8501, -2136.2011, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -151.8000, -37.1622, -115.5000, -160.3949, 0.0000, 0.0000, 0.0000, 0.0000, 114.3000, 297.9311, -146.4000, -145.8341, 0.0000, 0.0000, 94.9722, -211.8120, -207.3549, -528.6195, 320.4018, 466.9248, -105.6844, 222.9689, -4.5000, 76.2371, -30.5882, -367.8736, 0.3000, 0.8108, -90.5982, -110.4046, 295.8405, -175.2946, -668.8138, -1570.7035, 0.0000, 0.0000, 137.4000, 425.0978, -113.8812, -216.9466, 171.9000, 222.6649, 11.9564, -15.0839, 0.0000, 0.0000, 0.0000, 0.0000, 378.1700, 290.5888, -339.6906, -425.0982, -226.9572, -599.0342, 66.8762, 261.6348, -0.3000, -1.5789, -3.9000, -13.1573, 259.3683, 232.2913, 571.4586, 1086.6258, 0.0000, 0.0000, 808.3133, 1326.1995, 158.9015, 898.7495, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -25.8000, -9.4780, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -286.9958, 83.1784, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 448.8000, 926.4107, -105.7536, -48.3360, 0.0000, 0.0000, 8.7000, 77.4203, -342.6000, -436.7550, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 251.7000, 522.0795, 25.9223, 79.9107, 0.0000, 0.0000, 410.2168, 470.9758, -80.8020, -691.3658, 7.5000, -19.7585, 154.5911, 283.8591, 25.5000, 38.5823, -7.9794, 44.8809, 0.0000, 0.0000, 1.8000, -5.2549, 807.9013, 15.0467, 14.9928, 14.9928, 14.9507, 14.9928, 0.0421, 27.6152, 139.8023, -155.5465, 15.2377, 16.2126, 124.5646, -923.9555, -339.3944, -1588.3062, -1233.3061, 253.0938, 893.9117, 943.8573, 50.1837, 94.1054, 79.4541, -17.9685, 126.4395, 112.0739, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -12.3000, -7.1355, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -10.2000, -6.1853, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -5.4000, -5.2176, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 43.2000, 56.2045, 0.0000, 0.0000, 43.2000, 56.2045, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -127.4634, -545.8795, -643.2000, -1703.8056, 0.0000, 0.0000, 36.9000, 48.0269, -45.5961, -165.7502, 0.0000, 0.0000, 0.0000, 0.0000, -145.3095, -2116.6845, -232.3461, -56.6381, 0.0000, 0.0000, 0.0000, 0.0000, 82.3683, -8.9249, -176.2500, -1931.5789, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 59.1366, 165.4974, -170.0961, 464.2224, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -61.2000, -31.3716, -3.9000, -374.6094, 0.0000, 0.0000, 0.0000, 0.0000, 20.1000, 124.8812, -61.3500, 472.3893, 0.0000, 0.0000, -0.6000, -1.0075, -30.3000, 360.4326, -63.7134, -180.3475, -405.1500, -501.0898, 0.0000, 0.0000, -50.3961, -142.6871, -2.1000, -2.4836, -3.9000, -8.2519, 157.0500, 759.2604, -60.7500, -16.0084, 0.0000, 0.0000, -137.0634, -618.7643, -656.9961, -4871.3336, -252.8269, -100.2680, -327.0000, -765.4455, 0.0000, 0.0000, 0.0000, 0.0000, 400.2405, 1645.5402, -520.9461, -391.9776, -105.6000, 652.3781, 239.5500, 1463.3594, -6.9000, -19.4088, -2.7000, -3.9375, 110.8683, 194.5147, -181.6500, 437.3071, 0.0000, 0.0000, -57.6000, -46.6996, 366.9000, 1190.4603, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -27.9000, -18.5384, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2.6634, -173.7115, -447.4461, 155.9459, 0.0000, 0.0000, 114.0000, 281.4417, 26.5500, 595.2736, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -67.3317, -65.0544, -262.6500, -603.7141, 0.0000, 0.0000, 89.1000, 297.3484, 501.6000, 1933.4969, 158.1000, 678.0395, -70.0500, -135.7125, 69.0000, 201.4079, 210.4500, 880.2745, 0.0000, 0.0000, 0.0000, 0.0000, 262.5405, -24.8778, -24.8778, -24.8778, -24.8778, -24.8778, 0.0000, -247.4485, -18.3498, -318.3084, -543.0887, 13.3094, 524.7390, -1177.8014, -387.7585, -2187.9085, -1466.0865, -255.0085, 1078.3280, -2682.6305, 3.8090, 20.4821, 14.9058, -15.0625, 1.4684, 35.5446, 0.0000, 0.0000, 0.0000, 0.0000, 63.9000, 13.5722, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 5.4000, 1.2027, 5.4000, 1.2027, 0.0000, 0.0000, 13.8000, 3.5417, 8.4000, 2.3390, 0.0000, 0.0000, 0.0000, 0.0000, 16.8000, 4.6781, -11.7000, -195.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 32.4000, 7.2160, 27.6000, 7.0834, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 37.8000, 104.2861, 0.0000, 0.0000, 37.8000, 104.2861, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -11.7000, -195.0000, 192.0000, 47.4438, 0.0000, 0.0000, 0.0000, 0.0000, 61.2000, 16.4396, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 124.2000, 31.8754, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 66.6000, 17.6422, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -11.7000, -195.0000, 388.2000, 102.3780, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 13.8000, 3.5417, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 8.4000, 2.3390, 0.0000, 0.0000, 0.0000, 0.0000, 86.4000, 23.4567, 0.0000, 0.0000, 124.8000, 32.9454, 0.0000, 0.0000, 5.4000, 1.2027, 0.0000, 0.0000, 25.2000, 7.0171, 0.0000, 0.0000, 118.8000, 30.6727, 0.0000, 0.0000, -11.7000, -195.0000, 63.0000, 15.4358, -11.7000, -195.0000, 111.0000, 29.4037, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 161.4000, 43.4379, 0.0000, 0.0000, 38.4000, 9.4888, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 135.0000, 34.2807, 0.0000, 0.0000, 8.4000, 2.3390, 169.2000, 44.7069, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 584.4000, 248.9657, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 237.6000, 54.4080, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 296.4000, 77.7187, 0.0000, 0.0000, 8.4000, 2.3390, 97.2000, 25.8620, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 47.4000, 12.8979, 0.0000, 0.0000, 0.0000, 0.0000, 25.2000, 7.0171, 0.0000, 0.0000, 8.4000, 2.3390, 0.0000, 0.0000, 10.8000, 2.4053, 0.0000, 0.0000, 0.0000, 0.0000, 26.1000, -0.9834, -0.7592, -1.0392, -1.1400, -1.1400, 0.3808, 7.2183, 13.8612, 13.3232, -4.8746, -4.8746, 18.7358, 834.7200, 2129.4000, 1054.8000, -4.2000, -4.2000, 2133.6000, 3170.4000, -11.6563, -11.6156, -11.6698, -11.6698, -11.6698, 0.0543, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -129.0000, -119.4286, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 7.5000, 110.6723, 0.0000, 0.0000, 7.5000, 110.6723, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2.4000, 27.9687, 17.1000, 264.1854, 0.0000, 0.0000, 0.0000, 0.0000, -41.4000, 43.7143, 0.0000, 0.0000, 0.0000, 0.0000, 51.9000, 395.7143, 49.5000, 263.3683, 0.0000, 0.0000, 0.0000, 0.0000, -23.7000, -118.5000, -55.2000, -462.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.6000, 15.0000, -377.7000, -646.2143, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 6.9000, 50.8824, 48.0000, 440.4524, 0.0000, 0.0000, -29.7000, 87.5411, 82.5000, 525.2558, -31.8000, -75.2532, -45.3000, -2.5685, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -6.0000, -5.7143, 0.0000, 0.0000, 0.6000, 4.0000, -137.1000, -441.8571, -34.2000, 29.5133, -9.3000, 552.8794, 0.0000, 0.0000, 0.0000, 0.0000, -15.6000, -11.4286, -39.6000, -251.8571, 0.6000, 15.0000, -80.7000, -69.6429, 0.0000, 0.0000, -16.2000, -15.4286, -2.7000, 218.0641, 63.0000, 847.7818, 0.0000, 0.0000, -95.7000, -128.2962, -99.3000, 289.1309, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.6000, 4.2857, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -114.0000, 101.9160, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 10.8000, 71.2544, -318.6000, -16.0760, 0.0000, 0.0000, 0.0000, 0.0000, -16.2000, -15.4286, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 10.5000, 232.5000, -18.3000, -457.5000, 0.0000, 0.0000, -64.8000, -61.7143, -3.9000, -130.0000, 0.0000, 0.0000, -6.0000, -5.7143, 0.6000, 15.0000, -56.7000, 39.7857, 0.0000, 0.0000, 0.0000, 0.0000, -6.0000, 16.1625, 16.2000, 16.2000, 16.1250, 16.1250, 0.0750, 30.3001, 20.8306, 15.0435, 57.1526, 25.4317, -36.3220, -142.1605, -291.6000, -298.2000, 147.0000, -179.4000, -438.6000, -1398.9000, 5.6307, -9.1786, 12.2964, 14.4214, 12.7714, -23.6000, 0.0000, 0.0000, 0.0000, 0.0000, -0.3000, -0.3061, -119.7000, -233.7403, 5.4000, 3.7672, 0.0000, 0.0000, -63.0000, -125.4857, -63.0000, -125.4857, 180.3000, 512.8797, 0.0000, 0.0000, -199.9382, -68.2670, 17.5500, 406.3860, 116.5500, 893.4862, -1.8000, -2.5714, 13.5000, 37.1082, 3.3000, 2.2000, -7.2000, 67.5434, -784.2000, -246.6783, -29.7000, 49.5434, 0.0000, 0.0000, -318.1500, -431.7428, -60.0000, -37.1583, -476.1000, -303.7110, -29.7000, -46.7527, -0.9000, -1.2857, 0.0000, 0.0000, -0.9000, -1.2857, -0.6000, -0.4082, -21.6000, -1.7690, 0.0000, 0.0000, -66.0000, -53.9842, 0.0000, 0.0000, -494.1000, -607.2260, -873.0000, -961.5791, -529.9500, -506.8569, -403.5000, -317.8979, -362.8500, -436.3211, -410.7000, -482.7851, -263.1000, -335.8780, -311.1000, -358.8295, -381.3000, -353.0276, -378.3000, -335.5318, 1668.6000, 293.3002, 349.8000, 2076.4677, 0.0000, 0.0000, 636.9039, 520.9005, 176.1000, -373.2144, 0.0000, 0.0000, 0.0000, 0.0000, -164.5421, -375.4962, -468.3000, -731.1884, 0.0000, 0.0000, 0.0000, 0.0000, 32.1000, 397.1223, 432.4500, 1984.7681, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -80.5500, 683.9047, 66.0197, 2077.2822, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -51.0000, -91.8205, -235.3500, 78.0323, 0.0000, 0.0000, 0.0000, 0.0000, 196.5000, 16.2173, -26.2500, -377.0920, 0.0000, 0.0000, 158.1039, -253.7423, 400.2000, 2546.2180, 177.9079, 599.5291, 191.2500, 926.3556, 61.5000, 7.9722, 65.4000, 16.9686, 56.7000, 342.9643, -3.6000, -5.4775, 125.1039, 197.3464, 286.3579, 636.2457, 0.0000, 0.0000, -178.9461, -225.2515, 75.6000, 611.6029, 23.1039, -23.9727, 192.1539, 935.0015, 0.0000, 0.0000, 0.0000, 0.0000, -171.0000, -221.4278, -246.6000, 1069.0523, -138.7500, -68.0450, 79.5039, 708.1567, 431.7000, 93.3250, 0.6000, 15.2707, -188.3961, -87.1965, -309.6000, 1047.5576, 0.0000, 0.0000, -231.0000, -145.9550, 278.2658, 1101.6966, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -113.4000, -99.8992, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -1906.1882, 292.2818, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 42.4579, 722.7817, -202.4921, -421.2154, 0.0000, 0.0000, 70.5000, 233.0626, 68.4000, 418.6702, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 162.3000, 250.9940, -97.8000, -62.2382, 0.0000, 0.0000, -230.2500, -896.7380, 345.7579, 1186.5040, 77.4000, 246.7671, 10.5000, 488.1384, 89.1039, 285.6100, 129.9000, 265.2311, 72.0000, 34.0970, 66.6000, 43.9017, 428.2579, 143.4923, 142.9539, 142.9539, 144.0307, 142.9539, -1.0767, 305.7115, 339.0048, 349.0106, 307.4378, 428.2403, 31.5670, -1190.8989, 799.2789, -1133.6211, -2267.3487, -1527.8487, 3066.6276, -2155.0698, -10.3706, 5.7515, 9.7418, -27.9698, -28.9220, 33.7213, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -249.3000, -991.0256, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -23.4000, -154.2500, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 227.4000, -3430.8078, -101.9961, 222.0739, -34.8000, -1273.0426, -38.9961, -11.6525, -49.5000, 590.4748, -61.4921, 127.2970, -54.8921, 316.6081, -21.3000, -175.7871, 132.0000, 383.0615, 123.9000, 790.5378, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 41.1000, 256.8750, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 123.3000, 770.6250, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.6000, 8.5714, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -272.7000, -1145.2756, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 164.1000, 920.8354, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 681.9079, -16.4961, -16.4961, -16.4961, -16.4961, -16.4961, 0.0000, -175.1199, -109.6173, -181.4996, -167.0892, -205.7521, 57.4719, -316.9753, -237.5803, -336.2803, -296.9961, -365.0961, 59.4158, 176.7237, 11.2600, 33.1800, 0.3000, 0.3000, 0.3000, 32.8800, 0.0000, 0.0000, -132.9000, -178.3669, 75.6000, 4.3343, 1796.4000, 251.8180, 63.6000, 3.6763, 25.5000, 0.7518, 842.4000, 607.5978, 832.2000, 607.0309, 293.7000, 787.6672, 569.1000, 194.9054, 59.2683, -297.8625, 35.7000, -134.4535, -62.9817, -270.2255, 667.2000, 12.3995, 12.0000, 1.1831, 178.2000, 11.6507, 350.4000, 153.4938, -1395.3586, -1414.5201, 347.4000, 153.3421, 0.0000, 0.0000, 394.3500, -286.1239, -153.5634, -148.3141, -281.4951, 11.3732, 3.0000, 0.4151, 336.0000, 24.2724, -25.5000, -12.4773, 334.5000, 26.7810, -29.4000, -7.8838, 254.7000, 57.4955, 37.8000, 2.1671, 725.4000, 32.3579, 51.0000, -1.5938, -122.8317, -301.6609, -443.2134, -557.8598, -168.3000, -214.8677, -210.4500, -244.4421, -297.1500, -295.7788, -252.1500, -227.2214, -226.1634, -233.5016, -257.5317, -285.8991, -107.0634, -257.7936, -351.4317, -375.9785, -220.9903, -611.3071, -759.9000, -495.3385, 0.0000, 0.0000, -53.3634, -32.7631, 289.5000, -199.2135, 0.0000, 0.0000, 0.0000, 0.0000, -796.8037, -743.6031, -504.7500, -432.4888, 0.0000, 0.0000, -124.8000, -17.2376, -37.5000, 47.2265, -54.6000, 95.7039, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -690.0220, -720.1166, -39.3000, -518.6531, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -432.2451, -390.9087, -424.5000, -344.9166, 0.0000, 0.0000, 0.0000, 0.0000, -139.1634, 27.7525, 37.9500, 68.2241, 0.0000, 0.0000, -149.8317, -127.3728, -252.3000, 113.9034, -252.4537, -446.2015, -447.0000, 65.3878, -57.9000, 20.6723, 35.1000, -15.9457, -13.8000, -18.0397, -79.5000, -76.0875, -160.2951, -235.2479, -453.1500, -94.5193, -124.8000, -17.2376, -283.4634, -16.3269, 306.4500, 271.1454, 171.9000, 251.0841, 282.3000, -196.3963, 0.0000, 0.0000, 0.0000, 0.0000, -231.9951, -78.0414, -300.1500, -506.6687, -613.1451, -626.3086, 553.5000, -354.9814, 25.5000, 0.5667, 81.6000, 4.7268, 107.5866, -187.4397, -231.4500, -739.0432, 0.0000, 0.0000, -118.7269, -408.2263, -52.2000, -821.8106, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1306.1231, -293.3595, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 6079.4194, 175.6542, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -170.9269, -452.4080, 652.6500, 305.5387, 51.6000, 2.7121, -84.9000, -99.9721, 316.8000, -26.8054, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -346.2586, -330.7542, 162.0000, -61.0260, 0.0000, 0.0000, -169.8000, -161.7051, 247.5000, 57.8775, -91.6317, -75.0081, 81.3000, 3.8225, -84.1317, -93.1443, 357.3000, -76.6109, 36.3000, 13.4691, -14.7000, -2.6374, -114.5817, -123.1191, -123.2766, -123.2985, -122.9691, -122.9723, -0.3074, -724.0029, -722.4980, -722.6577, -725.5073, -724.3637, 3.0093, -434.0743, -26.8543, -36.1543, -838.0543, -154.0543, 811.2000, -191.5543, -70.4764, -69.1976, -69.5361, -71.5522, -69.6018, 2.3546, -19.5000, -2.2960, -2501.1000, -406.7270, 63.6000, -190.9229, 1652.7519, 439.5391, 132.6000, 4.6739, -167.9817, -100.0990, 1548.3276, 348.0933, 1557.0276, 352.0522, 258.6000, 58.2844, 691.2118, 32.3819, -1801.7933, -14.5966, 806.5697, 24.0957, -79.8327, 285.1060, 680.7577, 99.8437, 36.3000, -186.7175, 185.7000, 8.0167, 17.4000, -63.7953, -3078.9519, -55.2713, 14.4000, -63.9451, 5.4000, 0.4813, -207.5961, -266.9101, 1669.9312, -231.6890, -201.9332, 168.8494, -38.4000, -29.9763, 127.8046, 66.4108, -243.9000, -118.3104, 147.0046, 68.0975, -59.4000, -14.4856, 1762.5434, 108.9828, 128.4000, 14.9234, 686.1237, 71.9405, 62.8500, -20.9246, 1124.9888, -102.8993, -418.7889, -705.5622, -527.7312, -439.4388, -363.6273, -345.3711, -245.0982, -299.3409, -387.1421, -330.9946, -284.3538, -231.0643, 133.6683, -265.4654, -145.4634, -345.0809, -48.4317, -304.0646, 2026.9502, -359.7475, -2303.7725, -353.8773, 0.0000, 0.0000, 978.3405, -72.6340, 1585.3776, 159.8278, 0.0000, 0.0000, 0.0000, 0.0000, -1512.4165, -651.2064, -2504.9799, -973.0736, 0.0000, 0.0000, 0.0000, 0.0000, -469.0278, -241.9346, -157.8248, 222.3204, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -217.5709, -664.2356, -4016.9404, 558.7662, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -483.8412, -288.8564, -11.5773, 183.4783, 0.0000, 0.0000, 0.0000, 0.0000, 902.4366, 94.8582, 159.4658, -5.3031, 0.0000, 0.0000, 788.4445, 87.4278, 1169.6687, 595.7189, 774.6425, -13.8745, -3186.9044, -205.2954, 807.6000, 55.4359, 755.3846, -16.5074, 842.1000, 211.2810, 283.5136, -6.5076, 802.0176, 2.7841, -1614.8108, 209.2738, -21.0000, -8.1712, -444.9650, -567.6793, -424.8075, -168.5904, 767.7810, -195.3147, -1736.5678, 122.5441, 0.0000, 0.0000, 0.0000, 0.0000, 905.2154, 206.1462, -4591.2584, 162.5339, -594.2524, 12.8650, 1139.7236, 435.6136, 1122.3000, 104.9793, 622.2000, 128.9589, 699.5271, -23.1784, -1676.0861, 211.8682, 0.0000, 0.0000, 325.9944, 282.1952, -2274.7908, 236.9897, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 353.3056, -122.6358, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 3834.9152, 385.1061, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 281.3715, -269.6246, -2778.9142, -619.6105, 62.1000, 4.4704, 777.0000, 137.8802, 346.3737, 484.3283, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 378.1097, -75.7591, 658.1468, 538.0930, 0.0000, 0.0000, 665.6668, 794.5689, 2434.2716, 1374.0649, 891.7683, 189.9561, 484.7935, 524.9965, 1014.7722, 130.5094, 858.4359, 386.6370, 1077.3000, 187.1894, 1039.8018, 178.5105, 14.9928, 5.5429, 2.2732, 5.6239, 7.4114, 8.8660, -5.1382, 6.8471, 3.3402, 10.6644, -16.1887, -18.3430, 19.5289, 21.7661, -7.8721, 71.6279, -75.6721, 138.5279, 67.8000, 432.5279, -23.7078, -23.8699, -23.1137, -23.4926, -24.5326, -0.3773, 0.0000, 0.0000, -436.5000, -406.6747, 0.0000, 0.0000, 299.1079, 1254.5366, 1.8000, 3.3305, 3.0000, 3.3726, 226.2039, 368.4558, 226.2039, 368.4558, 27.0000, 37.3525, 552.9118, 1427.5870, -335.3961, -159.5723, -228.9000, -255.6403, -111.0000, -198.1610, 10.8000, 22.9464, 31.8000, 34.9833, 0.3000, 1.1111, 28.8000, 42.0848, 9.6000, 150.1236, 28.8000, 42.0848, 1.5000, 1.3191, -72.3000, 21.4608, -71.6921, -287.4289, -171.6000, -64.4781, 4.8000, 5.7791, -36.9000, -33.0645, 12.9000, 6.4137, -47.1000, -97.2233, 6.0000, 3.8698, 34.2000, -59.0559, 0.3000, 1.2000, 33.0000, 26.5820, 0.6000, 2.2650, 248.4000, -251.3096, -44.6961, -367.8892, -17.7000, -132.5680, -69.8961, -178.5608, -94.5000, -184.9899, 73.5079, 150.8177, -63.8921, -255.3799, 219.0000, 44.3097, 252.0000, 229.0293, 127.8000, 54.5115, 526.5000, 192.8233, -212.6961, 35.3431, 0.0000, 0.0000, 169.8000, 64.5751, 329.7000, 649.7758, 0.0000, 0.0000, 0.0000, 0.0000, 368.4000, 197.4486, -747.3000, -600.5747, 0.0000, 0.0000, 0.0000, 0.0000, -30.9000, -185.5367, -465.0000, -478.0432, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 220.2000, 106.1834, -454.2000, -5.4527, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 204.6000, 57.1477, 16.2000, 16.9019, 0.0000, 0.0000, 0.0000, 0.0000, 208.8000, 212.9356, 178.2039, 214.7414, 0.0000, 0.0000, 212.1000, 73.9813, 111.3039, 5.0197, 153.3000, 113.9097, -660.2961, -467.7522, 101.7000, 14.3714, 28.8000, -86.8844, 253.5000, 134.6303, -35.4000, -372.4010, 84.0000, 137.2707, -34.1961, 617.5050, 0.0000, 0.0000, 105.0000, 0.5490, 10.8000, -32.4046, 215.7000, 75.7576, -459.5961, -468.8989, 0.0000, 0.0000, 0.0000, 0.0000, 158.1000, 73.3350, -524.3961, -169.1004, 32.4000, -230.8868, 148.2039, 120.7425, 198.0000, 80.2743, 107.4000, 23.6735, 265.2000, 190.5917, -50.9921, 477.4438, 0.0000, 0.0000, 121.2039, 113.1928, -724.8000, -647.0624, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 191.4000, 342.9673, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 28.2394, 2264.0153, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 51.6039, 45.1648, -670.4921, -725.2843, 0.0000, 0.0000, 274.8000, 163.7878, -363.8961, 16.3195, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 350.4000, 474.3156, 42.3000, 1.6265, 0.0000, 0.0000, 123.0000, 63.4859, 237.9000, 461.2944, 292.5000, 192.8123, 59.1000, -88.8372, 197.7000, 117.9334, -81.0000, -106.7389, 129.9000, 18.3038, 161.4000, 36.1314, 174.6118, 22.9185, 23.6987, 23.6032, 22.5412, 23.0717, 1.1575, 104.2586, 118.7982, 44.9634, 114.7196, 126.5942, 4.0786, -289.6192, -482.9172, 368.4276, -465.2881, 1119.6119, -17.6290, 1784.2223, 37.3539, 37.1426, 36.7322, 41.0543, 27.7442, -3.9117, 0.0000, 0.0000, 21.0000, 36.1989, 0.0000, 0.0000, 52.5000, 88.2221, 0.0000, 0.0000, 0.0000, 0.0000, 142.8000, 90.3756, 142.8000, 90.3756, 49.8000, 20.4079, 2.1000, 1.2651, -40.2000, -482.9666, 4.2000, 1.8864, 16.2000, 6.8920, 0.0000, 0.0000, 4.8000, 3.2177, 0.0000, 0.0000, 31.8000, 22.4685, 4.5000, 1.5081, 31.8000, 22.4685, 0.0000, 0.0000, 22.5000, 15.1051, 102.6000, 91.9661, 48.9000, 32.2961, 17.7000, 34.0322, 20.4000, 10.8611, 54.9000, 34.0435, 20.4000, 10.8611, 0.0000, 0.0000, 21.6000, 26.1997, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -21.3000, -76.8633, -82.2000, -291.5558, 61.5000, 1.5584, 82.5000, 77.6278, -84.9000, -323.5277, -43.5000, -154.0897, -35.1000, -219.8170, -64.2000, -227.6659, -48.3000, -308.6288, 0.3000, 0.6522, 138.0000, 953.4850, -268.7921, -368.0715, 0.0000, 0.0000, 13.2000, -73.4391, 177.9000, 428.8695, 0.0000, 0.0000, 0.0000, 0.0000, -54.0000, 469.8090, -179.0961, -634.0828, 0.0000, 0.0000, 0.0000, 0.0000, -8.0961, 279.5197, -54.2961, 24.2867, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 53.1039, 267.8738, 23.1197, 963.2309, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -60.8961, -398.6077, 89.4000, 935.1044, 0.0000, 0.0000, 0.0000, 0.0000, 29.4000, 74.8166, 96.3079, 412.9985, 0.0000, 0.0000, 15.6000, 74.8610, -89.7000, -79.9771, 346.8000, 861.7655, 66.0158, 87.5193, 15.9000, 42.0900, 30.6000, 21.4977, 16.8000, 23.7562, 78.0000, 41.7713, 125.1000, 1188.4977, -45.2882, -748.6511, 0.0000, 0.0000, 75.6039, 81.2892, 11.1000, -84.9259, 187.8000, 629.3859, 25.2158, -82.5836, 0.0000, 0.0000, 0.0000, 0.0000, 125.1000, 919.4912, -156.8842, -353.2731, -30.0000, 97.3999, -168.2921, -441.1381, 18.0000, 24.8854, -8.1000, 11.0229, 75.3000, 45.6143, -266.9961, -297.0364, 0.0000, 0.0000, -47.6921, 69.7253, -109.1921, 745.9038, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 42.0000, 27.8985, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 773.1000, 157.6846, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -20.0961, -84.5141, -157.4842, 398.8845, 0.0000, 0.0000, -44.4000, -242.2642, 397.5000, 2081.6703, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 291.6000, 1031.6059, 112.2000, 462.8706, 0.0000, 0.0000, 40.8000, 374.6695, 24.6039, 71.4900, 20.1000, 47.5215, 1.5079, -277.2543, 12.6000, 31.6565, -117.6000, -380.8699, 15.6000, 72.7254, 17.7000, 84.2449, 338.7237, 85.3587, 85.5039, 85.5039, 84.8179, 85.5039, 0.6861, 205.2428, 231.6162, 162.4254, 252.6123, 71.8398, -20.9961, 622.9394, 1693.2473, 9.0316, 988.8158, -468.8803, 704.4316, 1460.5775, 67.0865, 91.5167, 83.4857, 52.2920, 86.7193, 39.2247, 8.1000, 2.7372, -1086.6000, -375.6314, 0.0000, 0.0000, 42.3000, 14.0124, 114.0000, -109.5158, 33.0000, 4.0675, 303.6000, 176.8241, 297.0000, 175.1687, 48.9000, -347.1646, -182.6961, 0.7177, -1747.9199, -679.5478, 818.1197, 400.6486, -435.8778, -222.7660, 71.1000, 272.3112, 66.9000, 92.3697, 9.6000, -9.6438, -34.5000, -42.7147, -2177.1546, -1500.0414, -34.5000, -42.7147, 5.4000, 2.2229, -363.1500, -197.6489, 114.0000, 586.8381, -429.0951, 264.1295, 19.2000, 13.0538, 26.7000, -35.4111, -35.1000, -197.5047, 55.5000, -30.8280, -21.6000, -10.2619, 725.7000, 88.2221, 90.6000, 30.3397, 65.4000, -154.0568, 109.5000, 30.4775, 1437.1683, -768.9696, 536.2866, -1292.5243, 67.2000, -716.3553, 31.9500, -734.6066, 131.2500, -810.2293, 83.5500, -324.7685, -37.1634, -790.7796, 455.8683, -490.4679, 255.6366, -415.8472, 206.8683, -398.2535, 475.9097, -864.3557, -1043.9921, -139.1409, 0.0000, 0.0000, 269.4366, -470.7438, 515.4000, -178.6790, 0.0000, 0.0000, 0.0000, 0.0000, -950.4037, -970.4569, -1211.5461, -1090.8617, 0.0000, 0.0000, 0.0000, 0.0000, -232.8000, -544.3594, -296.4000, -649.2534, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -485.7220, -1880.4330, -1356.8803, -821.0794, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -123.5451, -376.8129, 274.8000, 234.7818, 0.0000, 0.0000, 0.0000, 0.0000, 499.2366, -353.2639, 178.0579, 249.8559, 0.0000, 0.0000, 622.9683, 250.5238, 857.7039, 434.3439, 340.0463, -364.4502, -2334.8882, -1799.2715, 729.0000, 41.2605, 633.9000, -162.6550, 708.0000, 411.4282, 334.5079, -326.0608, 106.4049, -367.0317, -1233.4421, -452.2757, 0.0000, 0.0000, -152.3634, -577.0320, 363.7500, 251.9056, 746.1000, 122.3694, -1409.6961, -1309.4044, 0.0000, 0.0000, 0.0000, 0.0000, 298.4049, -385.1185, -2538.1421, -325.4895, -37.4451, -220.8733, 205.2158, 162.2845, 677.1000, -318.0013, 609.0000, 42.6112, 494.8866, -841.5100, -1446.1421, -858.6968, 0.0000, 0.0000, -136.1269, -505.9344, -1953.8961, -1356.1366, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1710.5231, -1456.8608, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -3523.5738, -1801.3109, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -287.9269, -853.5384, -1020.1303, 97.4049, 0.0000, 0.0000, 587.7000, -275.2914, 105.6079, 447.3907, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -165.9586, -366.3679, 331.8000, -113.1986, 0.0000, 0.0000, 416.7000, -158.8980, 1214.7000, 766.3825, 664.3683, 251.3333, 696.0079, 116.1176, 602.8683, -377.4676, 423.3079, -99.2015, 891.6000, 260.7725, 794.4000, 95.7752, 71.1656, -254.8950, -264.0270, -264.9945, -227.2922, -262.8387, -36.7348, -877.4115, -1082.9188, -888.8298, -705.0076, -894.5372, -377.9112, 1839.1613, 1249.6840, -685.0830, -154.3870, -20.2869, 1404.0710, -392.9937, -161.9402, -171.3577, -171.7278, -144.3884, -210.8031, -26.9693, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -161.4000, -122.5625, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 7.5000, 110.6723, 0.0000, 0.0000, 7.5000, 110.6723, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -2.4000, 27.9687, 17.1000, 266.9577, 0.0000, 0.0000, 0.0000, 0.0000, -57.6000, 39.3750, 0.0000, 0.0000, 0.0000, 0.0000, 51.9000, 395.7143, 33.3000, 250.7121, 0.0000, 0.0000, 0.0000, 0.0000, -23.7000, -118.5000, -55.2000, -462.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -15.6000, 2.3438, -442.5000, -646.9375, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 6.9000, 50.8824, 100.8000, 1320.4524, 0.0000, 0.0000, -29.7000, 95.8581, 82.5000, 525.2558, -31.8000, -72.4808, -8.7000, 872.0654, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -6.0000, -4.6875, 0.0000, 0.0000, 0.6000, 4.0000, -153.3000, -439.6250, -50.4000, 25.1740, 27.3000, 1430.2856, 0.0000, 0.0000, 0.0000, 0.0000, -15.6000, -8.6563, -55.8000, -258.9688, 0.6000, 15.0000, -96.9000, -68.4375, 0.0000, 0.0000, -16.2000, -12.6563, -2.7000, 226.3810, 115.8000, 1736.0988, 0.0000, 0.0000, -111.9000, -127.0909, -62.7000, 1181.4256, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.6000, 4.2857, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -146.4000, 98.7820, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 10.8000, 71.2544, -314.4000, 874.8303, 0.0000, 0.0000, 0.0000, 0.0000, -16.2000, -12.6563, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 10.5000, 232.5000, -18.3000, -457.5000, 0.0000, 0.0000, -81.0000, -63.2813, -3.9000, -130.0000, 0.0000, 0.0000, -22.2000, -17.3438, 0.6000, 15.0000, -72.9000, 38.2188, 0.0000, 0.0000, 0.0000, 0.0000, 30.6000, 68.9625, 69.0000, 69.0000, 68.9250, 68.9250, 0.0750, 164.5451, 152.9013, 151.5295, 193.6386, 161.9178, -40.7373, 161.9109, 25.2000, 51.0000, 463.8000, 137.4000, -438.6000, -1454.7000, 5.5309, -9.1786, 12.2964, 14.4214, 12.7714, -23.6000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 131.1000, -381.3078, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -18.9000, -24.3595, -56.4000, -98.3097, 0.0000, 0.0000, 106.5000, 126.0232, -18.3000, 20.3905, 0.0000, 0.0000, 0.0000, 0.0000, 131.7000, 291.1242, -93.3000, -732.9210, 0.0000, 0.0000, 0.0000, 0.0000, 45.9000, 43.4971, -75.9000, -557.1380, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -29.4000, -299.4224, 104.4000, -694.5302, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -9.0000, 38.0309, -87.3000, -630.8181, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 25.2000, 8.3708, 0.0000, 0.0000, -13.2000, -14.9775, -23.4000, -17.3123, 39.0000, 337.0705, -46.8000, -1446.0874, -21.0000, -37.5000, 0.0000, 0.0000, 0.0000, 0.0000, 0.9000, 4.6439, 0.0000, 0.0000, -150.3000, -744.9496, 0.0000, 0.0000, -20.4000, -36.4557, 39.3000, -239.2013, -16.2000, 27.9478, -87.0000, -690.1181, 0.0000, 0.0000, 0.0000, 0.0000, 38.7000, 103.4886, -115.2000, -1602.1478, 66.9000, -64.2248, 93.0000, 99.0590, 0.3000, 0.6977, -13.5000, -15.6752, -6.9000, 30.7944, 101.1000, -218.0019, 0.0000, 0.0000, 81.6000, 387.2837, 97.2000, -88.9094, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 131.1000, -381.3078, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 43.2000, 52.9879, 187.5000, 451.7453, 0.0000, 0.0000, 0.0000, 0.0000, -108.0000, -521.1141, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.6000, 10.2987, 63.0000, -53.4290, 0.0000, 0.0000, 9.0000, 66.4829, -2.1000, -4.7964, 0.3000, 0.6977, 32.4000, -5.4938, 0.6000, 8.7273, 62.4000, -30.1612, 0.0000, 0.0000, 0.0000, 0.0000, -36.3000, -71.4000, -71.4000, -71.4000, -71.4000, -71.4000, 0.0000, -182.6194, -220.8450, -198.0323, -153.3231, -101.9948, -67.5219, -852.8907, -1201.2000, -1360.8000, -381.6000, 110.4000, -819.6000, 489.3000, 12.4184, 6.5104, 7.7823, 19.2451, 16.5822, -12.7346, 0.0000, 0.0000, 0.0000, 0.0000, -27.6000, -2910.0000, 0.0000, 0.0000, 11.4000, 1050.0000, 2.1000, 90.0000, 0.0000, 0.0000, 6.9000, 30.0000, 0.0000, 0.0000, 0.0000, 0.0000, 10.5000, 1050.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 325.1745, 2881.8918, 0.0000, 0.0000, -34.2000, -39.3380, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 655.8039, -1799.5452, 0.0000, 0.0000, 0.0000, 0.0000, 9.0000, 66.5760, 27.0000, 154.4265, 0.0000, 0.0000, 27.0000, 154.4265, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -21.3000, -92.9167, 193.8000, 499.6664, 1.2000, 3.7500, -3.0000, -42.0000, -43.5000, -102.2842, -2.7000, -45.0000, -42.9000, -100.3069, -2.4000, -30.0000, -2.1000, -29.5238, -5.1000, -63.7500, -113.1000, 429.5003, -302.6541, -937.0656, 0.0000, 0.0000, -89.4000, -111.2983, 572.4079, 1524.9735, 0.0000, 0.0000, 0.0000, 0.0000, -311.6817, -1446.6664, 112.4806, 922.6393, 0.0000, 0.0000, 0.0000, 0.0000, -230.4000, -240.2807, 195.6262, -321.1331, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -327.8817, -1181.5688, -1173.2796, -1594.3245, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -52.2000, 30.8189, -192.0312, -194.0559, 0.0000, 0.0000, 0.0000, 0.0000, 1.2000, 3.7595, -135.0000, -436.3267, 0.0000, 0.0000, 3.9000, 10.0009, 87.9118, 510.2184, -350.4000, -251.9345, -225.5699, -1013.6835, 0.9000, 3.2143, 76.4688, 431.6988, 1.5000, 8.2143, -188.1000, -399.3520, -97.7817, 1428.1009, 341.1254, 1825.8989, 0.0000, 0.0000, -30.9000, 31.7028, 235.8197, 656.1123, 195.3000, 1604.9238, -62.1018, 2597.4403, 0.0000, 0.0000, 0.0000, 0.0000, -87.3000, -140.9125, -555.0033, -1279.2295, -194.7000, -120.9754, 705.0197, -578.2985, 0.6000, 5.4545, 2.7000, 467.2122, -169.2000, -19.4120, -167.9724, -1157.7486, 0.0000, 0.0000, -119.4000, 39.3299, -640.7699, -430.7979, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 1009.7784, 1418.4377, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 66.0000, 212.0348, -712.1341, -2775.8041, 0.0000, 0.0000, 21.9000, 1383.0182, -2.3842, -465.6471, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, 0.0000, -18.6000, 18.8991, 442.7745, 3144.8217, 0.0000, 0.0000, 19.5000, 47.2059, 368.1118, 890.4916, 9.3000, 40.9160, -289.1817, -892.8081, 0.6000, 0.7595, 331.8035, 746.0012, 0.0000, 0.0000, 111.9018, 507.1677, 1741.5519, 49.4928, 49.4928, 49.4928, 49.4928, 49.4928, 0.0000, 32.7036, 96.2196, -8.6715, 99.1979, 5.7007, -2.9783, -54.9792, -473.6772, -234.8969, 472.7913, -172.1969, -946.4684, -1852.4971, 19.9326, 11.4960, 23.3641, 30.4160, 23.7506, -18.9200)
    
    # Set appropriate $weightedVector value, defaulting to the higher confidence weighted vector ($highConfidenceWeightedVector) unless the -Deep or -CommandLine switches are specified.
    if ($Deep.IsPresent)
    {
        $weightedVector = $broadNetWeightedVector
    }
    elseif ($CommandLine.IsPresent)
    {
        $weightedVector = $commandLineWeightedVector
    }
    else
    {
        $weightedVector = $highConfidenceWeightedVector
    }

    # The number of elements in the input $FeatureVector array and the pre-generated $weightedVector array must be equal in order to accurately measure the obfuscation level of the input $FeatureVector array.
    # This mismatch will occur if: 1) check scripts are altered or removed, 2) additional check scripts are added to the Checks directory, or 3) an updated $weightedVector array is added above.
    if ($FeatureVector.Count -ne ($weightedVector.Count - 1))
    {
        Write-Error "Feature count mismatch ($($FeatureVector.Count) -ne $($weightedVector.Count - 1))"
    }

    [System.Double] $obfuscationProbability = $weightedVector[0]

    for ($i = 0; $i -lt ($weightedVector.Length - 1); $i++)
    {
        $obfuscationProbability += ($weightedVector[$i + 1] * $FeatureVector[$i])
    }

    $weight = 1.0 / (1.0 + [Math]::Exp(-$obfuscationProbability))
    
    if ($weight -gt 0.5)
    {
        $obfuscated = $true
    }
    else
    {
        $obfuscated = $false
    }

    # Return result as a PSCustomObject.
    [PSCustomObject] @{
        Obfuscated = [System.Boolean] $obfuscated
        ObfuscatedScore = [System.Double] $weight
    }
}

# 将checks中定义的获取特征的方法以及Helpers中的方法加载到Powershell的Session中
function Add-CSharpCheck
{
<#
.SYNOPSIS

Add-CSharpCheck compiles (via Add-Type) all CSharp .cs check files located in the Checks directory and adds the compiled class/method pairs to the $script:cSharpCheckMethods variable for later retrieval and check invocations in the Get-RvoFeatureVector function.

Revoke-Obfuscation Helper Function: Add-CSharpCheck
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Add-CSharpCheck compiles (via Add-Type) all CSharp .cs check files located in the Checks directory and adds the compiled class/method pairs to the $script:cSharpCheckMethods variable for later retrieval and check invocations in the Get-RvoFeatureVector function.

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    Write-Verbose "Compiling CSharp Check Functions"
    Write-Verbose "Add-Type -Path .\Requirements\RevokeObfuscationHelpers.cs,.\Checks\*.cs -PassThru"
    
    # Add-Type函数: 将.NET类添加到Powershell session中
    # Compile required CSharp helper functions in the .\Requirements\ directory and feature extraction check functions in the .\Checks\ directory.
    $outputTypes = Add-Type -Path $scriptDir\Requirements\RevokeObfuscationHelpers.cs,$scriptDir\Checks\*.cs -PassThru
    
    # Add compiled CSharp functions to $script:cSharpCheckMethods for later reference when extracting features from input script.
    $script:cSharpCheckMethods = @()
    foreach ($outputType in $outputTypes | Where-Object { $_.GetMethod("AnalyzeAst") })
    {
        $className = $outputType.Name
        $methodName = "AnalyzeAst"

        $script:cSharpCheckMethods += , @($className , $methodName)
        
        Write-Verbose "Check Compiled :: [$className]::$methodName"
    }
}


function Update-RvoWhitelist
{
<#
.SYNOPSIS

Update-RvoWhitelist computes SHA256 hashes for any scripts located in the $whitelistDir directory and adds these hashes and any content and/or regular expression whitelist rule names and terms defined in Strings_To_Whitelist.txt and Regex_To_Whitelist.txt files in the Whitelists directory to their respective arrays. These arrays are used by the Check-Whitelist function to whitelist defined scripts and script content when using the Measure-RvoObfuscation function.

Revoke-Obfuscation Helper Function: Update-RvoWhitelist
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Update-RvoWhitelist computes SHA256 hashes for any scripts located in the $whitelistDir directory and adds these hashes and any content and/or regular expression whitelist rule names and terms defined in Strings_To_Whitelist.txt and Regex_To_Whitelist.txt files in the Whitelists directory to their respective arrays. These arrays are used by the Check-Whitelist function to whitelist defined scripts and script content when using the 7fuscation function.

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    # Query all scripts in the $whitelistDir directory that we will hash as whitelisted scripts.
    $script:whitelistHashArray = @()
    if (Test-Path $whitelistDir)
    {
        $whitelistFiles = Get-ChildItem $whitelistDir

        # Compute hash for each file in $whitelistFiles directory and add hash to $script:whitelistHashArray.
        foreach ($file in $whitelistFiles)
        {
            # Read in file for hashing to maintain parity with scripts ingested through non-file means (like from event logs).
            $scriptContent = Get-Content -Path $file.FullName -Raw

            # Compute hash for $fileToWhitelist.
            $ms = New-Object System.IO.MemoryStream
            $sw = New-Object System.IO.StreamWriter $ms
            $sw.Write($scriptContent)
            $sw.Flush()
            $sw.BaseStream.Position = 0
            $hash = (Get-FileHash -InputStream $sw.BaseStream -Algorithm SHA256).Hash

            # Add result as a PSCustomObject.
            $script:whitelistHashArray += , [PSCustomObject] @{
                Name  = [System.String] $file.FullName
                Value = [System.String] $hash
            }
        }
        
        Write-Verbose "Computed hashes for $($whitelistFiles.Count) file(s) in whitelist directory $whitelistDir"
    }
    
    # Read in content of $whitelistContentFile into an array.
    $script:whitelistStringArray = @()
    if (Test-Path $whitelistContentFile)
    {
        # Parse out each line into an array of termName and termValue for more description behind each whitelisted result (and forced auditing of why a particular whitelist rule was added).
        Get-Content $whitelistContentFile | Where-Object { $_.Length -ne 0 } | ForEach-Object {
            $termName  = $_.Substring(0,$_.IndexOf(','))
            $termValue = $_.Substring($_.IndexOf(',') + 1)

            # Add result as a PSCustomObject.
            $script:whitelistStringArray += , [PSCustomObject] @{
                Name  = [System.String] $termName
                Value = [System.String] $termValue
            }
        }
    }
    
    Write-Verbose "Loaded $($script:whitelistStringArray.Count) whitelisted string(s) from $whitelistContentFile"

    # Read in content of $whitelistRegexFile into an array.
    $script:whitelistRegexArray = @()
    if (Test-Path $whitelistRegexFile)
    {
        # Parse out each line into an array of termName and termValue for more description behind each whitelisted result (and forced auditing of why a particular whitelist rule was added).
        Get-Content $whitelistRegexFile | Where-Object { $_.Length -ne 0 } | ForEach-Object {
            $termName  = $_.Substring(0,$_.IndexOf(','))
            $termValue = $_.Substring($_.IndexOf(',') + 1)

            # Add result as a PSCustomObject.
            $script:whitelistRegexArray += , [PSCustomObject] @{
                Name  = [System.String] $termName
                Value = [System.String] $termValue
            }
        }
    }
    
    Write-Verbose "Loaded $($script:whitelistRegexArray.Count) whitelisted regex(es) from $whitelistRegexFile"
}


function Check-Whitelist
{
<#
.SYNOPSIS

Check-Whitelist checks input script against all values in the three whitelisting avenues (SHA256, content/string whitelist, RegEx whitelist) set in the Update-RvoWhitelist function. Check-Whitelist returns a PSCustomObject containing information about the whitelisting result, including (if whitelisted) the whitelist type, rule name and value that matched.

Revoke-Obfuscation Helper Function: Check-Whitelist
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Check-Whitelist checks input script against all values in the three whitelisting avenues (SHA256, content/string whitelist and RegEx whitelist) set in the Update-RvoWhitelist function. Check-Whitelist returns a PSCustomObject containing information about the whitelisting result, including (if whitelisted) the whitelist type, rule name and value that matched.

.PARAMETER ScriptContent

Specifies the PowerShell script expression to check against all values in the three whitelist value arrays (SHA256, content/string and RegEx).

.PARAMETER Hash

Specifies the SHA256 hash of the input PowerShell script expression.

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $ScriptContent,
        
        [Parameter(Position = 0, Mandatory = $true)]
        [System.String]
        $Hash
    )
    
    # If input hash is found in $script:whitelistHashArray or $script:whitelistArgHashArray (populated during Measure-RvoObfuscation invocation via -WhitelistFile argument) then return positive match information in PSCustomObject.
    if (($script:whitelistHashArray + $script:whitelistArgHashArray).Value -contains $Hash)
    {
        # Retrieve matching whitelist term, selecting the first match in case there are duplicates.
        $whitelistTerm = ($script:whitelistHashArray + $script:whitelistArgHashArray) | Where-Object { $_.Value -eq $Hash } | Select-Object -First 1
        
        # Return result as a PSCustomObject.
        return [PSCustomObject] @{
            Match = [System.Boolean] $true
            Type  = [System.String] 'Whitelisted Hash'
            Name  = [System.String] $whitelistTerm.Name
            Value = [System.String] $whitelistTerm.Value
        }
    }   
    
    # If any single string value in $script:whitelistStringArray or $script:whitelistArgStringArray (populated during Measure-RvoObfuscation invocation via -WhitelistContent argument) is found in $scriptContent then return positive match information in PSCustomObject.
    foreach ($whitelistTerm in ($script:whitelistStringArray + $script:whitelistArgStringArray))
    {
        if ($scriptContent.Contains($whitelistTerm.Value))
        {
            # Return result as a PSCustomObject.
            return [PSCustomObject] @{
                Match = [System.Boolean] $true
                Type  = [System.String] 'Whitelisted String'
                Name  = [System.String] $whitelistTerm.Name
                Value = [System.String] $whitelistTerm.Value
            }
        }
    }
    
    # If any single regex value in $script:whitelistRegexArray or $script:whitelistArgRegexArray (populated during Measure-RvoObfuscation invocation via -WhitelistRegex argument) is found in $scriptContent then return positive match information in PSCustomObject.
    foreach ($whitelistTerm in ($script:whitelistRegexArray + $script:whitelistArgRegexArray))
    {
        if ($scriptContent -match $whitelistTerm.Value)
        {
            # Return result as a PSCustomObject.
            return [PSCustomObject] @{
                Match = [System.Boolean] $true
                Type  = [System.String] 'Whitelisted Regex'
                Name  = [System.String] $whitelistTerm.Name
                Value = [System.String] $whitelistTerm.Value
            }
        }
    }
    
    # Return $false (not whitelisted) as a PSCustomObject if no matches in above whitelist checks.
    return [PSCustomObject] @{
        Match = [System.Boolean] $false
        Type  = [System.String] 'Not Whitelisted'
        Name  = [System.String] 'Not Whitelisted'
        Value = [System.String] 'Not Whitelisted'
    }
}

# 通过在checks中定义的一系列方法，获取脚本的所有特征向量，以哈希表的形式返回
function Get-RvoFeatureVector
{
<#
.SYNOPSIS

Get-RvoFeatureVector extracts thousands of features from input script via execution of all AST-based (Abstract Syntax Tree) .cs check files located in the Checks directory and returns them as an ordered hashtable. These features can be compared to weighted vectors in the Measure-RvoObfuscation function to determine obfuscation level.

Revoke-Obfuscation Function: Get-RvoFeatureVector
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-RvoFeatureVector extracts thousands of features from input script via execution of all AST-based (Abstract Syntax Tree) .cs check files located in the Checks directory and returns them as an ordered hashtable. These features can be compared to weighted vectors in the Measure-RvoObfuscation function to determine obfuscation level.

.PARAMETER Path

Specifies the path to the PowerShell script from which the function will extract features.

.PARAMETER ScriptExpression

Specifies the PowerShell script expression from which the function will extract features.

.PARAMETER ScriptBlock

Specifies the PowerShell script block from which the function will extract features.

.EXAMPLE

C:\PS> Get-RvoFeatureVector -Path .\Demo\DBOdemo1.ps1

.EXAMPLE

C:\PS> Get-ChildItem .\Demo\DBOdemo2.ps1 | Get-RvoFeatureVector

.EXAMPLE

C:\PS> Get-RvoFeatureVector -ScriptExpression (Get-Content -Raw .\Demo\DBOdemo1.ps1)

.EXAMPLE

C:\PS> Get-Content -Raw .\Demo\DBOdemo2.ps1 | Get-RvoFeatureVector

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Path')]
        [System.IO.FileInfo]
        $Path,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ScriptExpression')]
        [System.String[]]
        $ScriptExpression,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'ScriptBlock')]
        [ScriptBlock[]]
        $ScriptBlock
    )
    
    # Handle various input formats to produce the same data format in the $scriptContent variable.
    switch ($PSCmdlet.ParameterSetName)
    {
        "Path" {
            # Read in file path as an expression.
            $scriptContent = Get-Content -Path $Path -Raw
        }
        "ScriptExpression" {
            $scriptContent = [System.String] $ScriptExpression
        }
        "ScriptBlock" {
             # Treat an input script block as an expression from an AST parsing perspective.
            $scriptContent = [System.String] $ScriptBlock
        }
    }

    # Parse $scriptContent into an AST object.
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent,[Ref] $null,[Ref] $null)
    
    # 保存所有的特征向量到哈希表中
    # Create ordered hashtable to store all CheckScript results for current AST object.
    $allCheckScriptResults = [Ordered] @{}

    # Execute each checkScript method compiled from CSharp check scripts against input AST object.
    foreach ($checkScript in $script:cSharpCheckMethods)
    {
        # Invoke current checkScript.
        $checkScriptResult = $null
        try
        {
            # 调用该check中定义的 AnalyzeAst
            # $checkScript[0] => classname
            # $checkScript[1] => AnalyzeAst
            $checkScriptResult = ([Type] $checkScript[0])::($checkScript[1]).Invoke($ast)
        }
        catch
        {
            Write-Error $ErrorMessage
        }

        # Add current CheckScript results to total result hashtable.
        if ($checkScriptResult)
        {
            # Results from CSharp checks are converted to SortedDictionary objects so there is no need to sort results here.
            $allCheckScriptResults += $checkScriptResult
        }
        else
        {
            Write-Error "No results were returned from current check: [$($checkScript[0])]::$($checkScript[1])"
        }
    }

    # Return combined results from all checkScript method invocations.
    return $allCheckScriptResults
}


function Get-RvoScriptBlock
{
<#
.SYNOPSIS

Get-RvoScriptBlock extracts and reassembles PowerShell scripts and commands from script block logs found in PowerShell Operational event log EID 4104 events, returning them as a PSCustomObject with additional metadata fields (like % reassembled, log level, time created, etc.).

Revoke-Obfuscation Function: Get-RvoScriptBlock
Authors: Daniel Bohannon (@danielhbohannon) and Lee Holmes (@Lee_Holmes)
License: Apache License, Version 2.0
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Get-RvoScriptBlock extracts and reassembles PowerShell scripts and commands from script block logs found in PowerShell Operational event log EID 4104 events, returning them as a PSCustomObject with additional metadata fields (like % reassembled, log level, time created, etc.).

.PARAMETER Path

Specifies the path to PowerShell Operational event log(s). Handles .evt/.evtx and MIR/HX event log audit file formats.

.PARAMETER EventLogRecord

Specifies the event log record format produced when running Get-WinEvent cmdlet against an event log or .evt/.evtx event log file on disk or in memory.

.PARAMETER CimInstance

Specifies the event log record format returned when querying a local or remote event log with Get-CSEventLogEntry cmdlet in Matt Graeber's (@mattifestation) CimSweep framework.
CimSweep: https://github.com/PowerShellMafia/CimSweep
An additional registry key must be added to trick WMI into querying a non-classic event log (PowerShell Operational event log).
See the NOTES section for sample syntax to add this registry key and start using CimSweep's Get-CSEventLogEntry cmdlet.
Thanks to noted Blue Teamer Matt Graeber (@mattifestation) for this information and technique.

.PARAMETER Deep

(Optional) Returns all script blocks (bypassing the default unique'ing functionality of this function) and does not discard common default script block values defined in the $scriptBlockValuesToIgnoreForReduceSwitch variable at the beginning of the function.

.PARAMETER Verbose

(Optional) Displays verbose status of event record parsing and reassembling.

.EXAMPLE

C:\PS> Get-RvoScriptBlock -Path 'C:\Windows\System32\Winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'

.EXAMPLE

C:\PS> Get-ChildItem .\Demo\demo.evtx | Get-RvoScriptBlock -Verbose

.EXAMPLE

C:\PS> Get-ChildItem C:\MirOrHxAuditFiles\*_w32eventlogs.xml | Get-RvoScriptBlock -Verbose

.EXAMPLE

C:\PS> Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Get-RvoScriptBlock -Deep

.EXAMPLE

C:\PS> Get-CSEventLogEntry -LogName Microsoft-Windows-PowerShell/Operational | Get-RvoScriptBlock

.NOTES

This is a personal project developed by Daniel Bohannon and Lee Holmes while employees at MANDIANT, A FireEye Company and Microsoft, respectively.

Follow below steps (as admin) to use CimSweep's Get-CSEventLogEntry cmdlet to query local or remote PowerShell Operational event logs.

# Step 1: Trick WMI to read a modern event log by adding this registry value to your target system (below example is just for local system).
$HKLM = [UInt32] 2147483650

$MethodArgs = @{
    Namespace = 'root/default'
    ClassName = 'StdRegProv'
    MethodName = 'CreateKey'
    Arguments = @{
        HDefKey = $HKLM
        SSubKeyName = 'SYSTEM\CurrentControlSet\Services\EventLog\Microsoft-Windows-PowerShell/Operational'
    }
}

Invoke-CimMethod @MethodArgs

# Step 2: Download/Import CimSweep core functions.
Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/CimSweep/master/CimSweep/Core/CoreFunctions.ps1')

# Step 3: Query modern PowerShell event log.
Get-CSEventLogEntry -LogName Microsoft-Windows-PowerShell/Operational | Where-Object { $_.EventIdentifier -eq 4104 }

.LINK

http://www.danielbohannon.com
http://www.leeholmes.com/blog/
#>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'Path')]
        [Alias('File')]
        [System.String]
        $Path,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'EventLogRecord')]
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]
        $EventLogRecord,
        
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'CimInstance')]
        [PSTypeName("Microsoft.Management.Infrastructure.CimInstance#root/cimv2/Win32_NTLogEvent")]
        $CimInstance,
        
        [Parameter(Mandatory = $false)]
        [Switch]
        $Deep
    )
    
    # Handle various input formats to produce the same data format in the $EventLogRecord variable.
    switch ($PSCmdlet.ParameterSetName)
    {
        "Path" {
            # If $Path is passed into this function via the pipeline then the function will only handle the first item.
            # So we will validate and copy $input to $inputFiles to get the full array of objects from the pipeline.
            if (($input.Count -gt 0) -and ($input.GetType().Name -eq 'Object[]') -and ($input[0].GetType().Name -eq 'FileInfo'))
            {
                $inputFiles = $input
            }
            else
            {
                $inputFiles = Get-ChildItem -Path $Path
            }

            # Throw warning to user for large numbers of file paths being input into Get-RvoScriptBlock as processing may take significantly longer depending on the number and size of input files.
            if ($inputFiles.Count -gt 10)
            {
                Write-Warning "Currently processing $($inputFiles.Count) files. Depending on the size of the files this could take several minutes.`n         For faster performance try passing one file at a time into Get-RvoScriptBlock."
            }
            
            # Read event logs from input event log or MIR/HX event log audit file path(s) and query out script block logs (EID 4104) from input PowerShell Operatrional event log.
            $curFileCount = 0
            $EventLogRecord = $inputFiles | ForEach-Object {
                $curFileCount++
                $Header = [System.Char[]](Get-Content $_ -Encoding Byte -TotalCount 75) -join ''

                # Handle various file formats for ingesting PowerShell event log records.
                if ($Header.StartsWith('ElfFile'))
                {
                    # Handle .evt/.evtx file format.
                    Write-Verbose "Parsing $curFileCount of $($inputFiles.Count) .evt/.evtx file(s) :: $($_.Name)"

                    # Throw warning if file extension is not .evt/.evtx (Get-WinEvent requires .evt/.evtx/.etl file extensions).
                    if (-not $_.Name.EndsWith('.evt') -and -not $_.Name.EndsWith('.evtx'))
                    {
                        Write-Warning "File is event log but does not end in .evt/.evtx which the Get-WinEvent cmdlet requires.`n         Please rename to .evt or .evtx extension.`n         File: $($_.Name)"
                    }
                    else
                    {
                        # Catch exception when no events are present in event log.
                        try
                        {
                            Get-WinEvent -Path $_.FullName -ErrorAction Stop | Where-Object { $_.id -eq 4104 }
                        }
                        catch [System.Exception]
                        {
                            # Display caught error if it is not the below known error when no events are present in event log.
                            if ($_.Exception.ToString() -ne 'System.Exception: No events were found that match the specified selection criteria.')
                            {
                                Write-Error $_
                            }
                        }
                    }
                }
                elseif ($Header.StartsWith('<?xml version=') -and $Header.Contains('<itemList generator="w32eventlogs"'))
                {
                    # Handle MIR/HX event log audit file format.
                    Write-Verbose "Parsing $curFileCount of $($inputFiles.Count) MIR/HX audit file(s) :: $($_.Name)"

                    # MIR/HX audits need to have html entities decoded.
                    Add-Type -AssemblyName System.Web
        
                    # Query out script block logs (EID 4104) from input MIR/HX event log audit.
                    # Perform renaming so that structure matches that of [System.Diagnostics.Eventing.Reader.EventLogRecord] objects.
                    [Object[]] $EventLogRecord = ([xml](Get-Content $auditfile)).ItemList.EventLogItem | Where-Object { $_.EID -eq 4104 } |  Select-Object `
                        @{ Name = 'id'              ; Expression = { $_.EID } },
                        @{ Name = 'TimeCreated'     ; Expression = { $_.GenTime } },
                        @{ Name = 'LevelDisplayName'; Expression = { $_.Type } },
                        @{ Name = 'Properties'      ; Expression = { `
                            @(
                                @{ Value = ( $_.Message.Split("`n") | Select-Object -First 1 ).Split(' ()')[4] },
                                @{ Value = ( $_.Message.Split("`n") | Select-Object -First 1 ).Split(' ()')[6] },
                                # Two layers of html decoding for instances like &amp;quot; where the first decoding results in &quot; and the second decoding results in the final "
                                @{ Value = ( $_.Message.Split("`n") | ForEach-Object { [System.Web.HttpUtility]::HtmlDecode([System.Web.HttpUtility]::HtmlDecode($_)) } | Select-Object -Skip 1 | Select-Object -SkipLast 4) -join "`n" },
                                @{ Value = ( $_.Message.Split("`n") | Select-Object -Last 3 | Select-Object -First 1 ).Replace('ScriptBlock ID: ','').Trim() }
                            )
                        }
                    }

                    $EventLogRecord
                }
                else
                {
                    # Not a recognized file format. Let's just run Get-WinEvent, hope for the best, and let Get-WinEvent break the news to the user.
                    Write-Verbose "Parsing $curFileCount of $($inputFiles.Count) unrecognized format file(s) :: $($_.Name)"

                    Get-WinEvent -Path $_.FullName | Where-Object { $_.id -eq 4104 }
                }
            }
        }
        "EventLogRecord" {
            # If $EventLogRecord is passed into this function via the pipeline then the function will only handle the first item.
            # So we will validate and copy $input to $EventLogRecord to get the full array of objects from the pipeline.
            if (($input.Count -gt 0) -and ($input.GetType().Name -eq 'Object[]') -and ($input[0].GetType().Name -eq 'EventLogRecord'))
            {
                $EventLogRecord = $input
            }

            # Query out script block logs (EID 4104) from input PowerShell Operational event log (Get-WinEvent).
            $EventLogRecord = $EventLogRecord | Where-Object { $_.id -eq 4104 }
        }
        "CimInstance" {
            # If $CimInstance is passed into this function via the pipeline then the function will only handle the first item.
            # So we will validate and copy $input to $CimInstance to get the full array of objects from the pipeline.
            if (($input.Count -gt 0) -and ($input.GetType().Name -eq 'Object[]') -and ($input[0].GetType().Name -eq 'CimInstance'))
            {
                $CimInstance = $input
            }

            # Query out script block logs (EID 4104) from input PowerShell Operational event log (CimSweep's Get-CSEventLogEntry).
            # Perform renaming so that structure matches that of [System.Diagnostics.Eventing.Reader.EventLogRecord] objects.
            [Object[]] $EventLogRecord = $CimInstance | Where-Object { $_.EventIdentifier -eq 4104 } | Select-Object `
                @{ Name = 'id'              ; Expression = { $_.EventIdentifier } },
                @{ Name = 'TimeCreated'     ; Expression = { $_.TimeGenerated.DateTime } },
                @{ Name = 'LevelDisplayName'; Expression = { $_.Type } },
                @{ Name = 'Properties'      ; Expression = { `
                    @(
                        @{ Value = $_.InsertionStrings[0] },
                        @{ Value = $_.InsertionStrings[1] },
                        @{ Value = $_.InsertionStrings[2] },
                        @{ Value = $_.InsertionStrings[3] }
                    )
                }
            }
        }
    }
    
    Write-Verbose "Grouping and reassembling script blocks from the input $($EventLogRecord.Count) event log record(s)."

    # Set exact script block values to ignore (unless the -Deep flag is set). This is to reduce noise for default script block values that we might not care about.
    $scriptBlockValuesToIgnoreForReduceSwitch  = @()
    $scriptBlockValuesToIgnoreForReduceSwitch += '$global:?'
    $scriptBlockValuesToIgnoreForReduceSwitch += 'prompt'
    $scriptBlockValuesToIgnoreForReduceSwitch += 'exit'
    $scriptBlockValuesToIgnoreForReduceSwitch += '{ Set-StrictMode -Version 1; $_.ErrorCategory_Message }'
    $scriptBlockValuesToIgnoreForReduceSwitch += '{ Set-StrictMode -Version 1; $_.OriginInfo }'
    $scriptBlockValuesToIgnoreForReduceSwitch += '{ Set-StrictMode -Version 1; $_.PSMessageDetails }'
    $scriptBlockValuesToIgnoreForReduceSwitch += '{ Set-StrictMode -Version 1; $this.Exception.InnerException.PSMessageDetails }'

    # Create an array to house all (reassembled) unique script block values to only return unique script blocks (unless the -Deep switch is set).
    $UniqueScriptBlocks = @()
    
    # Grouping and sorting all script block events (EID 4104) to reassemble and add corresponding metadata to resultant array of PSCustomObjects.
    # Base code taken from https://blogs.msdn.microsoft.com/powershell/2015/06/09/powershell-the-blue-team/ per the Blue Team master, Lee Holmes (@Lee_Holmes).
    ($EventLogRecord | Group-Object { $_.Properties[3].Value } | ForEach-Object { $_.Group | Group-Object { $_.Properties[0].Value } } | ForEach-Object { $_.Group[0] }) | Group-Object {$_.Properties[3].Value} | ForEach-Object {
        $sortedScripts = $_.Group | Sort-Object { $_.Properties[0].Value }
        $mergedScript = ($sortedScripts | ForEach-Object { $_.Properties[2].Value }) -join ''
        
        # Use continue variable to decide if reassembled script block should continue in metadata enrichment process.
        $continue = $true
        if (-not $Deep)
        {
            # Skip processing reassembled script block since it is contained in the whitelisted array and the -Deep switch is not set.
            if ($scriptBlockValuesToIgnoreForReduceSwitch -ccontains $mergedScript)
            {
                $continue = $false
            }
            elseif ($UniqueScriptBlocks -ccontains $mergedScript)
            {
                # Skip processing reassembled script block since it is a duplicate and the -Deep switch is not set.
                $continue = $false
            }
            else
            {
                # -Deep flag is not set and reassembled script block is not in $scriptBlockValuesToIgnoreForReduceSwitch or $UniqueScriptBlocks.
                # Therefore, add to $UniqueScriptBlocks array and continue with metadata enrichment process.
                $UniqueScriptBlocks += $mergedScript
            }
        }
        
        # Store reassembled script block results and corresponding metadata in a PSCustomObject.
        if ($continue)
        {
            $scriptBlockId = [System.String] $_.Name
            $recordCount = $_.Group.Count
    
            if ($recordCount -gt 1)
            {
                $timeCreated = [System.DateTime] $_.Group.TimeCreated[0]
                $eid = [System.Uint16] $_.Group.Id[0]
                $levelDisplayName = [System.String] $_.Group.LevelDisplayName[0]
            }
            else
            {
                $timeCreated = [System.DateTime] $_.Group.TimeCreated
                $eid = [System.Uint16] $_.Group.Id
                $levelDisplayName = [System.String] $_.Group.LevelDisplayName
            }

            $scriptBlockChunkCount = [System.Uint16] $_.Group.Count
            $scriptBlockChunkTotal = [System.Uint16] $_.Group.Properties[1].Value

            if($scriptBlockChunkCount -eq $scriptBlockChunkTotal)
            {
                $reassembled = [System.Boolean] $true
            }
            else
            {
                $reassembled = [System.Boolean] $false
            }

            # Build final PSCustomObject to house reassembled script blocks and corresponding metadata for each script ID.
            [PSCustomObject] @{
                PSTypeName            = "RevokeObfuscation.RvoScriptBlockResult"
                ScriptBlock           = [System.String] $mergedScript
                ScriptBlockLength     = [System.Uint32] ($mergedScript -Join '').Length
                ScriptBlockId         = [System.String] $scriptBlockId
                TimeCreated           = [System.DateTime] $timeCreated
                Id                    = [System.UInt16] $eid
                LevelDisplayName      = [System.String] $levelDisplayName
                Reassembled           = [System.Boolean] $reassembled
                ScriptBlockChunkCount = [System.UInt16] $scriptBlockChunkCount
                ScriptBlockChunkTotal = [System.UInt16] $scriptBlockChunkTotal
                ReassembledPercent    = [System.Double] $scriptBlockChunkCount / [System.Double] $scriptBlockChunkTotal
            }
        }
    }

    # Null out $UniqueScriptBlocks since it is no longer needed.
    $UniqueScriptBlocks = $null
}


# Get current directory of .ps1 script no matter the working directory.
$scriptDir = Split-Path -Parent $myInvocation.MyCommand.Definition

# Set whitelist directory and content and regex whitelist files. All scripts located in this directory and content/regex in these files will be automatically whitelisted by Measure-RvoObfuscation cmdlet.
$whitelistDir         = "$scriptDir\Whitelist\Scripts_To_Whitelist"
$whitelistRegexFile   = "$scriptDir\Whitelist\Regex_To_Whitelist.txt"
$whitelistContentFile = "$scriptDir\Whitelist\Strings_To_Whitelist.txt"

# Set results directory.
$resultObfuscatedDir  = "$scriptDir\Results\Obfuscated"

# 将check方法和helper中的方法加载到当前 session 中
Add-CSharpCheck

switch ($PSCmdlet.ParameterSetName)
{
    "Csv" {
        # Read in Url(s) as an expression.
        # for item in csv, Measure-RvoObfuscation -Path item
        $labeledData = @{}
        Import-Csv $Csv | % { 
            $result = Measure-RvoObfuscation -Path $_.path -Verbose
            $labeledData[$_.path] = 0
            if ($result.obfuscated) {
                $labeledData[$_.path] = 1
            }
        } 
        # todo 将检测结果保存到csv中
        $labeledData.GetEnumerator() | 
        Select-Object -Property @{N='path';E={$_.Key}}, @{N='label';E={$_.Value}} | 
        Export-Csv -NoTypeInformation -Path result.csv
    }

    "File" {
        $result = Measure-RvoObfuscation -Path $File -Verbose
        write-output $result.ObfuscatedScore
    }
}