WORKING_DIRS=tmp
SRC=$(shell find . -name "*.go")
BIN=tmp/$(shell basename $(CURDIR))
FMT=tmp/fmt
TEST=tmp/cover
DOC=Document.txt

.PHONY: all clean cover test

all: $(WORKING_DIRS) $(FMT) $(BIN) $(TEST) $(DOC)

clean:
	rm -rf $(WORKING_DIRS)

$(WORKING_DIRS):
	mkdir -p $(WORKING_DIRS)

$(FMT): $(SRC)
	go fmt ./... > $(FMT) 2>&1 || true

go.sum: go.mod
	go mod tidy

$(BIN): $(SRC) go.sum
	go build -o $(BIN)

$(TEST): $(BIN)
	make test

test:
	go test -v -tags=mock -cover -coverprofile=$(TEST) ./...

$(DOC): $(SRC)
	go doc -all . > $(DOC)

cover: $(TEST)
	grep "0$$" $(TEST) || true
