Date /T >>  %USERPROFILE%\Map_drive.txt
Time /T >>  %USERPROFILE%\Map_drive.txt
ECHO Starting with the Network mapped drive >>  %USERPROFILE%\Map_drive.txt

net use E: \\DCB0211-FS.learn.taleocloud.prd\rds_data$ >>  %USERPROFILE%\Map_drive.txt