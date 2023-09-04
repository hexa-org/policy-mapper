echo "Building 4 sub-modules in workspace..."

echo "  hexaIdql."

cd ./hexaIdql
go mod tidy
go build ./...
cd ..

echo "  mapper/conditionLangs/gcpcel."
cd mapper/conditionLangs/gcpcel
go mod tidy
go build ./...
cd ../../..

echo "  mapper/formats/awsCedar."
cd mapper/formats/awsCedar
go mod tidy
go build ./...
cd ../../..

echo "  mapper/formats/gcpBind."
cd mapper/formats/gcpBind
go mod tidy
go build ./...
cd ../../..

echo "  mapTool."
go mod tidy
go build -o mapTool cmd/mapTool/main.go
