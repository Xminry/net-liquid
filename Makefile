VERSION=develop
gomod:
	go get chainmaker.org/chainmaker/common/v2@$(VERSION)
	go get chainmaker.org/chainmaker/protocol/v2@$(VERSION)
	go get chainmaker.org/chainmaker/net-common@$(VERSION)
	go mod tidy
	cat go.mod|grep chainmaker

