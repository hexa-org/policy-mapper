doTest () {
  if [ "$test" = 'Y' ];then
    echo "   running tests..."
    go test ./...
  fi
}

test="N"
while getopts "t" OPTION; do
  case "$OPTION" in
    t)
      echo "Build and test requested."
      test="Y"
      ;;
  esac
done

echo "Policy Mapper installation"
echo "  building..."
go build ./...
doTest
echo "  installing..."
go install ./...
printf "Start Hexa CLI by using the 'hexa' command.\nIf the command is not found, check that the go/bin directory is in your PATH.\n"
exit

# This section is for when policy-models is multi-module - not currently used

echo "Building 5 sub-modules in workspace..."


# go work sync

echo " pkg "

cd ./pkg
go build ./...
doTest
cd ..

echo "  mapper/conditionLangs/gcpcel."
cd models/conditionLangs/gcpcel
go build ./...
doTest
cd ../../..

echo "  mapper/formats/awsCedar."
cd models/formats/awsCedar
go build ./...
doTest
cd ../../..

echo "  mapper/formats/gcpBind."
cd models/formats/gcpBind
go build ./...
doTest
cd ../../..

echo "  providers/aws."
cd providers/aws
go build ./...
doTest
cd ../..

echo "  mapTool."
cd cmd/mapTool
go build -o ../../mapTool main.go
doTest
cd ../../