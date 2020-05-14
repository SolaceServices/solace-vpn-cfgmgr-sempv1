[ $# -lt 1 ] && { echo missing file arg; exit; }
mkdir org > /dev/null 2>&1
for f  do
echo "processing file $f"
mv $f org/
sed 's/+[A-Z_]*+/%s/g' org/$f > $f
done
