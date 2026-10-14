<#
.SYNOPSIS
Generate offline female British English narration as a WAV file for the demo.
.DESCRIPTION
Run with Windows PowerShell 5.1. Uses an installed Windows speech voice;
no network service, API key, microphone, or speaker playback is used.
The default output is ignored by Git. Add the WAV as an OBS Media Source
when preparing the recording, or align it with captured footage in editing.
This script does not configure OBS or start a recording.
Install English (United Kingdom) under Windows Settings > Time & language >
Speech > Manage voices > Add voices first. Restart PowerShell after installation.
.EXAMPLE
.\scripts\New-DemoNarration.ps1
.EXAMPLE
.\scripts\New-DemoNarration.ps1 -InputPath .\my-narration.txt -OutputPath .\.lab\demo\narration.wav
#>
param(
    [string]$InputPath = (Join-Path $PSScriptRoot '..\docs\demo\narration-sample.txt'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\.lab\demo\narration-sample.wav'),
    [string]$VoiceName = '',
    [ValidateRange(0.5, 2.0)][double]$Rate = 0.95,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$speechType = [Windows.Media.SpeechSynthesis.SpeechSynthesizer, Windows.Media.SpeechSynthesis, ContentType=WindowsRuntime]
$streamType = [Windows.Media.SpeechSynthesis.SpeechSynthesisStream, Windows.Media.SpeechSynthesis, ContentType=WindowsRuntime]
$inputFile = (Resolve-Path -LiteralPath $InputPath).ProviderPath
$outputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([IO.Path]::GetExtension($outputFile) -ine '.wav') {
    throw 'OutputPath must end in .wav.'
}
if ($inputFile -ieq $outputFile) { throw 'Input and output must be different files.' }
if ((Test-Path -LiteralPath $outputFile) -and -not $Force) {
    throw 'Output already exists. Choose another path or use -Force to replace it.'
}
$narration = Get-Content -LiteralPath $inputFile -Raw -Encoding UTF8
if ([string]::IsNullOrWhiteSpace($narration)) { throw 'Narration text is empty.' }
$voice = $speechType::AllVoices | Where-Object {
    $_.Language -eq 'en-GB' -and [string]$_.Gender -eq 'Female' -and
    ([string]::IsNullOrWhiteSpace($VoiceName) -or $_.DisplayName -eq $VoiceName)
} | Sort-Object DisplayName | Select-Object -First 1
if (-not $voice) {
    throw 'No matching female UK English voice is installed. Add English (United Kingdom) in Windows Settings > Time & language > Speech > Manage voices > Add voices, then restart PowerShell.'
}
$synth = New-Object $speechType.FullName
$speechStream = $null
$audioStream = $null
$fileStream = $null
try {
    $synth.Voice = $voice
    $synth.Options.SpeakingRate = $Rate
    $operation = $synth.SynthesizeTextToStreamAsync($narration)
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and
        $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    } | Select-Object -First 1
    $task = $asTask.MakeGenericMethod($streamType).Invoke($null, @($operation))
    $speechStream = $task.GetAwaiter().GetResult()
    $audioStream = [System.IO.WindowsRuntimeStreamExtensions]::AsStreamForRead($speechStream)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($outputFile)) | Out-Null
    $mode = if ($Force) { [IO.FileMode]::Create } else { [IO.FileMode]::CreateNew }
    $fileStream = [IO.File]::Open($outputFile, $mode, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $audioStream.CopyTo($fileStream)
    $fileStream.Dispose()
    $fileStream = $null
    [pscustomobject]@{
        Path = $outputFile
        Voice = $voice.DisplayName
        Culture = $voice.Language
        Rate = $Rate
        Bytes = (Get-Item -LiteralPath $outputFile).Length
    }
} finally {
    if ($fileStream) { $fileStream.Dispose() }
    if ($audioStream) { $audioStream.Dispose() }
    if ($speechStream) { $speechStream.Dispose() }
    $synth.Dispose()
}
