echo "Building 5 sub-modules in workspace..."

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

# go work sync

echo "  pkg."

cd ./pkg
go build ./...
doTest
cd ..

echo "  mapper/conditionLangs/gcpcel."
cd mapper/conditionLangs/gcpcel
go build ./...
doTest
cd ../../..

echo "  mapper/formats/awsCedar."
cd mapper/formats/awsCedar
go build ./...
doTest
cd ../../..

echo "  mapper/formats/gcpBind."
cd mapper/formats/gcpBind
go build ./...
doTest
cd ../../..

echo "  mapTool."
cd cmd/mapTool
go build -o ../../mapTool main.go
doTest
cd ../../