param(
    [Parameter(Mandatory=$true)][ValidateSet('speech','video','inspect')][string]$Mode,
    [Parameter(Mandatory=$true)][string]$DemoRoot
)
$ErrorActionPreference='Stop'
$demoResolved=[IO.Path]::GetFullPath($DemoRoot)
if (-not $demoResolved.StartsWith('D:\VulnGym-bv2-runtime\delivery\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected output scope' }
if ($Mode -eq 'speech') {
    Add-Type -AssemblyName System.Speech
    $demoScenes=Get-Content -LiteralPath (Join-Path $demoResolved 'storyboard.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $demoAudioDir=Join-Path $demoResolved 'audio'
    if (Test-Path -LiteralPath $demoAudioDir) { throw 'Audio directory already exists' }
    New-Item -ItemType Directory -Path $demoAudioDir | Out-Null
    $demoSynth=New-Object System.Speech.Synthesis.SpeechSynthesizer
    try {
        $demoSynth.SelectVoice('Microsoft Huihui Desktop')
        $demoSynth.Rate=0
        foreach ($demoScene in $demoScenes) {
            $demoWave=Join-Path $demoAudioDir ('scene-{0:00}.wav' -f $demoScene.index)
            if (Test-Path -LiteralPath $demoWave) { throw 'Wave output exists' }
            $demoFormat=New-Object System.Speech.AudioFormat.SpeechAudioFormatInfo(22050,[System.Speech.AudioFormat.AudioBitsPerSample]::Sixteen,[System.Speech.AudioFormat.AudioChannel]::Mono)
            $demoSynth.SetOutputToWaveFile($demoWave,$demoFormat)
            $demoSynth.Speak([string]$demoScene.voice)
            $demoSynth.SetOutputToNull()
        }
    } finally { $demoSynth.Dispose() }
    Write-Output '{"speech_created":true,"voice":"Microsoft Huihui Desktop","synthetic":true,"online_calls":0}'
    exit 0
}
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null=[Windows.Storage.StorageFile,Windows.Storage,ContentType=WindowsRuntime]
$null=[Windows.Storage.StorageFolder,Windows.Storage,ContentType=WindowsRuntime]
$null=[Windows.Media.Editing.MediaClip,Windows.Media.Editing,ContentType=WindowsRuntime]
$null=[Windows.Media.Editing.MediaComposition,Windows.Media.Editing,ContentType=WindowsRuntime]
$null=[Windows.Media.Editing.BackgroundAudioTrack,Windows.Media.Editing,ContentType=WindowsRuntime]
$null=[Windows.Media.MediaProperties.MediaEncodingProfile,Windows.Media.MediaProperties,ContentType=WindowsRuntime]
$null=[Windows.Media.Transcoding.TranscodeFailureReason,Windows.Media.Transcoding,ContentType=WindowsRuntime]
function Wait-DemoOperation([object]$Operation,[type]$ResultType) {
    $demoMethod=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    $demoTask=$demoMethod.MakeGenericMethod($ResultType).Invoke($null,@($Operation))
    $demoTask.GetAwaiter().GetResult()
}
function Wait-DemoProgress([object]$Operation,[type]$ResultType,[type]$ProgressType) {
    $demoMethod=[System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetGenericArguments().Count -eq 2 -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperationWithProgress`2' } | Select-Object -First 1
    $demoTask=$demoMethod.MakeGenericMethod($ResultType,$ProgressType).Invoke($null,@($Operation))
    $demoTask.GetAwaiter().GetResult()
}
$demoVideoPath=Join-Path $demoResolved 'T2-existing-results-demo.mp4'
if ($Mode -eq 'video') {
    if (Test-Path -LiteralPath $demoVideoPath) { throw 'Video output exists; preserve before any retry' }
    $demoTimeline=Get-Content -LiteralPath (Join-Path $demoResolved 'timeline.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $demoComposition=New-Object Windows.Media.Editing.MediaComposition
    foreach ($demoScene in $demoTimeline.scenes) {
        $demoImagePath=Join-Path $demoResolved $demoScene.image
        $demoFile=Wait-DemoOperation ([Windows.Storage.StorageFile]::GetFileFromPathAsync($demoImagePath)) ([Windows.Storage.StorageFile])
        $demoClip=Wait-DemoOperation ([Windows.Media.Editing.MediaClip]::CreateFromImageFileAsync($demoFile,[TimeSpan]::FromSeconds($demoScene.duration_seconds))) ([Windows.Media.Editing.MediaClip])
        [System.Collections.Generic.ICollection[Windows.Media.Editing.MediaClip]].GetMethod('Add').Invoke($demoComposition.Clips,@($demoClip))
    }
    $demoAudioFile=Wait-DemoOperation ([Windows.Storage.StorageFile]::GetFileFromPathAsync((Join-Path $demoResolved 'narration.wav'))) ([Windows.Storage.StorageFile])
    $demoTrack=Wait-DemoOperation ([Windows.Media.Editing.BackgroundAudioTrack]::CreateFromFileAsync($demoAudioFile)) ([Windows.Media.Editing.BackgroundAudioTrack])
    [System.Collections.Generic.ICollection[Windows.Media.Editing.BackgroundAudioTrack]].GetMethod('Add').Invoke($demoComposition.BackgroundAudioTracks,@($demoTrack))
    $demoFolder=Wait-DemoOperation ([Windows.Storage.StorageFolder]::GetFolderFromPathAsync($demoResolved)) ([Windows.Storage.StorageFolder])
    $demoOutput=Wait-DemoOperation ($demoFolder.CreateFileAsync('T2-existing-results-demo.mp4',[Windows.Storage.CreationCollisionOption]::FailIfExists)) ([Windows.Storage.StorageFile])
    $demoProfile=[Windows.Media.MediaProperties.MediaEncodingProfile]::CreateMp4([Windows.Media.MediaProperties.VideoEncodingQuality]::HD720p)
    $demoProfile.Video.FrameRate.Numerator=15
    $demoProfile.Video.FrameRate.Denominator=1
    $demoProfile.Video.Bitrate=700000
    $demoProfile.Audio.Bitrate=96000
    $demoProfile.Audio.ChannelCount=1
    $demoResult=Wait-DemoProgress ($demoComposition.RenderToFileAsync($demoOutput,[Windows.Media.Editing.MediaTrimmingPreference]::Precise,$demoProfile)) ([Windows.Media.Transcoding.TranscodeFailureReason]) ([double])
    if ($demoResult -ne [Windows.Media.Transcoding.TranscodeFailureReason]::None) { throw ('Encoding failed: '+$demoResult) }
    Write-Output '{"video_encoded":true,"codec_requested":"H264/AAC","width":1280,"height":720,"fps":15}'
} else {
    $demoVideoFile=Wait-DemoOperation ([Windows.Storage.StorageFile]::GetFileFromPathAsync($demoVideoPath)) ([Windows.Storage.StorageFile])
    $demoProperties=Wait-DemoOperation ($demoVideoFile.Properties.GetVideoPropertiesAsync()) ([Windows.Storage.FileProperties.VideoProperties,Windows.Storage,ContentType=WindowsRuntime])
    [pscustomobject]@{width=$demoProperties.Width;height=$demoProperties.Height;duration_seconds=$demoProperties.Duration.TotalSeconds;bitrate=$demoProperties.Bitrate} | ConvertTo-Json -Compress
    $demoInspectRoot=Join-Path $demoResolved 'decoded-qa'
    if (Test-Path -LiteralPath $demoInspectRoot) { throw 'Decoded QA output already exists' }
    New-Item -ItemType Directory -Path $demoInspectRoot | Out-Null
    $demoTimeline=Get-Content -LiteralPath (Join-Path $demoResolved 'timeline.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $demoReadClip=Wait-DemoOperation ([Windows.Media.Editing.MediaClip]::CreateFromFileAsync($demoVideoFile)) ([Windows.Media.Editing.MediaClip])
    $demoReadComposition=New-Object Windows.Media.Editing.MediaComposition
    [System.Collections.Generic.ICollection[Windows.Media.Editing.MediaClip]].GetMethod('Add').Invoke($demoReadComposition.Clips,@($demoReadClip))
    $demoChecks=@()
    foreach ($demoScene in $demoTimeline.scenes) {
        $demoSeconds=[double]$demoScene.start_seconds + [double]$demoScene.duration_seconds/2
        $demoThumbnail=Wait-DemoOperation ($demoReadComposition.GetThumbnailAsync([TimeSpan]::FromSeconds($demoSeconds),1280,720,[Windows.Media.Editing.VideoFramePrecision]::NearestFrame)) ([Windows.Graphics.Imaging.ImageStream,Windows.Graphics.Imaging,ContentType=WindowsRuntime])
        $demoImageType=$demoThumbnail.ContentType
        if ($demoImageType -eq 'image/jpeg') { $demoSuffix='jpg' } elseif ($demoImageType -eq 'image/png') { $demoSuffix='png' } else { throw 'Unknown decoded thumbnail type' }
        $demoImageName=('scene-{0:00}.{1}' -f $demoScene.index,$demoSuffix)
        $demoReadStream=[System.IO.WindowsRuntimeStreamExtensions]::AsStreamForRead($demoThumbnail)
        $demoWriteStream=[IO.File]::Open((Join-Path $demoInspectRoot $demoImageName),[IO.FileMode]::CreateNew)
        try { $demoReadStream.CopyTo($demoWriteStream) } finally { $demoWriteStream.Dispose(); $demoReadStream.Dispose() }
        $demoChecks += [pscustomobject]@{scene=$demoScene.index;at_seconds=$demoSeconds;file=$demoImageName;type=$demoImageType}
    }
    $demoInspection=[pscustomobject]@{width=$demoProperties.Width;height=$demoProperties.Height;duration_seconds=$demoProperties.Duration.TotalSeconds;bitrate=$demoProperties.Bitrate;decoded_frames=$demoChecks}
    $demoJson=$demoInspection | ConvertTo-Json -Depth 5 -Compress
    [IO.File]::WriteAllText((Join-Path $demoInspectRoot 'metadata.json'),$demoJson,(New-Object Text.UTF8Encoding($false)))
    [pscustomobject]@{decoded_frames=$demoChecks.Count;video_read_only=$true} | ConvertTo-Json -Compress
}
