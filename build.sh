echo "Building 5 sub-modules in workspace..."

go work sync

echo "  hexaIdql."

cd ./hexaIdql
go build ./...
cd ..

echo "  mapper/conditionLangs/gcpcel."
cd mapper/conditionLangs/gcpcel
go build ./...
cd ../../..

echo "  mapper/formats/awsCedar."
cd mapper/formats/awsCedar
go build ./...
cd ../../..

echo "  mapper/formats/gcpBind."
cd mapper/formats/gcpBind
go build ./...
cd ../../..

echo "  mapTool."
go build -o mapTool cmd/mapTool/main.go
