$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$projectRoot=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$source=[Drawing.Image]::FromFile((Join-Path $projectRoot 'assets/phone-exit-icon.png'))
function IconPng([int]$size){
    $bitmap=[Drawing.Bitmap]::new($size,$size)
    $graphics=[Drawing.Graphics]::FromImage($bitmap)
    $stream=[IO.MemoryStream]::new()
    try{
        $graphics.InterpolationMode='HighQualityBicubic';$graphics.PixelOffsetMode='HighQuality'
        $graphics.DrawImage($source,[Drawing.Rectangle]::new(0,0,$size,$size))
        $bitmap.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
        return ,$stream.ToArray()
    }finally{$stream.Dispose();$graphics.Dispose();$bitmap.Dispose()}
}
try{
    $windowsAssets=Join-Path $projectRoot 'pc/assets'
    [IO.File]::WriteAllBytes((Join-Path $windowsAssets 'phone-exit.png'),(IconPng 256))
    $sizes=@(16,24,32,48,64,128,256)
    $frames=@($sizes | ForEach-Object { ,(IconPng $_) })
    $stream=[IO.MemoryStream]::new();$writer=[IO.BinaryWriter]::new($stream)
    try{
        $writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$sizes.Count)
        $offset=6+16*$sizes.Count
        for($i=0;$i -lt $sizes.Count;$i++){
            $dimension=if($sizes[$i] -eq 256){0}else{$sizes[$i]}
            $writer.Write([byte]$dimension);$writer.Write([byte]$dimension)
            $writer.Write([byte]0);$writer.Write([byte]0);$writer.Write([uint16]1);$writer.Write([uint16]32)
            $writer.Write([uint32]$frames[$i].Length);$writer.Write([uint32]$offset)
            $offset+=$frames[$i].Length
        }
        foreach($frame in $frames){$writer.Write([byte[]]$frame)}
        [IO.File]::WriteAllBytes((Join-Path $windowsAssets 'phone-exit.ico'),$stream.ToArray())
    }finally{$writer.Dispose();$stream.Dispose()}
    $resources=Join-Path $projectRoot 'android/app/src/main/res'
    foreach($entry in @(@('mdpi',48),@('hdpi',72),@('xhdpi',96),@('xxhdpi',144),@('xxxhdpi',192))){
        $folder=Join-Path $resources ('mipmap-'+$entry[0]);[IO.Directory]::CreateDirectory($folder)|Out-Null
        [IO.File]::WriteAllBytes((Join-Path $folder 'ic_launcher.png'),(IconPng $entry[1]))
    }
    $brandFolder=Join-Path $resources 'drawable-nodpi';[IO.Directory]::CreateDirectory($brandFolder)|Out-Null
    [IO.File]::WriteAllBytes((Join-Path $brandFolder 'phone_exit_brand.png'),(IconPng 512))
    Write-Output 'App icon sizes generated for Windows and Android.'
}finally{$source.Dispose()}
