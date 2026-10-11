function WriteApplicationRules($tree,[string]$file) {
    $paths=@($tree.Poll())
    $json=@{version=3;rules=@(@{process_path_regex=@($paths|ForEach-Object{'(?i)^'+[regex]::Escape($_)+'$'})})}|ConvertTo-Json -Depth 6 -Compress
    if(!(Test-Path -LiteralPath $file) -or [IO.File]::ReadAllText($file) -ne $json){
        # Replace in-place atomically: sing-box watches this local rule set.
        $temp=$file+'.new';[IO.File]::WriteAllText($temp,$json,[Text.UTF8Encoding]::new($false))
        if(Test-Path -LiteralPath $file){[IO.File]::Replace($temp,$file,[NullString]::Value)}else{[IO.File]::Move($temp,$file)}
    }
    return $paths.Count
}
