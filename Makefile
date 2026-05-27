.PHONY: all build test clean

EXTENSIONS := mac_enclosure_color

all: build

build:
	@for ext in $(EXTENSIONS); do \
		echo "Building $$ext.ext..."; \
		cd $$ext && GOOS=darwin go build -o $$ext.ext . && cd ..; \
	done

test:
	@for ext in $(EXTENSIONS); do \
		cd $$ext && go test ./... && cd ..; \
	done

clean:
	@for ext in $(EXTENSIONS); do \
		rm -f $$ext/$$ext.ext; \
		rm -rf $$ext/$$ext.ext.dSYM; \
	done
