param()

New-Item -ItemType Directory -Force -Path 'src-tauri\icons' | Out-Null
Add-Type -AssemblyName System.Drawing

$sizes = @(32, 128, 256)
foreach ($sz in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $sz, $sz
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::FromArgb(255, 13, 17, 23))
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 0, 229, 255), [Math]::Max(2, [int]($sz/16)))
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 0, 229, 255))
    $g.DrawEllipse($pen, [float]($sz*0.2), [float]($sz*0.2), [float]($sz*0.6), [float]($sz*0.6))
    $g.FillEllipse($brush, [float]($sz*0.4), [float]($sz*0.4), [float]($sz*0.2), [float]($sz*0.2))
    $g.Dispose()

    if ($sz -eq 32) {
        $bmp.Save('src-tauri\icons\32x32.png', [System.Drawing.Imaging.ImageFormat]::Png)
        $hIcon = $bmp.GetHicon()
        $icon = [System.Drawing.Icon]::FromHandle($hIcon)
        $fs = [System.IO.File]::OpenWrite('src-tauri\icons\icon.ico')
        $icon.Save($fs)
        $fs.Close()
        $fs = [System.IO.File]::OpenWrite('src-tauri\icons\icon.icns')
        $bmp.Save($fs, [System.Drawing.Imaging.ImageFormat]::Png)
        $fs.Close()
    } elseif ($sz -eq 128) {
        $bmp.Save('src-tauri\icons\128x128.png', [System.Drawing.Imaging.ImageFormat]::Png)
    } elseif ($sz -eq 256) {
        $bmp.Save('src-tauri\icons\128x128@2x.png', [System.Drawing.Imaging.ImageFormat]::Png)
    }
    $bmp.Dispose()
}
Write-Host "Icons generated successfully"
