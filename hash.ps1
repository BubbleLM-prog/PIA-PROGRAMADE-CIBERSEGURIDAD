param($rutaHash)
[string]$fecha = Get-Date -Format "dd_MM_yyyy_HH_mm_ss"
[string]$archivo = 'Reportes/Hash_' + $fecha + '.txt'
Get-ChildItem  $rutaHash | Get-FileHash | Select-Object -Property Hash, Path | Format-Table -AutoSize | Out-File $archivo -Encoding ascii
