#!/bin/bash

# directories should be separated by spaces and have the ending slash /
MONITORED_FOLDERS=(~/Downloads)
MONITORED_FILES_SAVE_LOCATION=monitored-files
FIM_BASELINE_FILE=fim-baseline

if [ -f $FIM_BASELINE_FILE ]
then
    fimReportFile=fim-report-`date +%Y-%m-%d-%H-%M-%S`
else
    fimReportFile=$FIM_BASELINE_FILE
fi

for folder in ${MONITORED_FOLDERS[@])}
do  
    echo "[*] Calculating hashes for files in" $folder
    find $folder* -type f > $MONITORED_FILES_SAVE_LOCATION

    while read -r filePath; do
        echo $(md5sum "$filePath") >> $fimReportFile
    done < $MONITORED_FILES_SAVE_LOCATION
done

rm $MONITORED_FILES_SAVE_LOCATION
echo "[*] FIM report saved in" $fimReportFile
echo "[*] Comparing $fimReportFile with $FIM_BASELINE_FILE"
diff $FIM_BASELINE_FILE $fimReportFile



